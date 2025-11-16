// Main dashboard functions

const dashboardPage = document.getElementById('dashboardPage');
const currentFilter = {
    selectedLabel: dashboardPage?.dataset.selectedLabel || '',
    forceAll: dashboardPage?.dataset.forceAll === '1',
    inboxLabel: dashboardPage?.dataset.inboxLabel || ''
};
const autoSyncMinutesFromDataset = Number(dashboardPage?.dataset.autoSyncMinutes || 0);
window.MAILORG_AUTO_SYNC_MINUTES = autoSyncMinutesFromDataset;
const confirmDeleteEnabled = window.Mailosophy_REQUIRE_DELETE_CONFIRM !== false;

const quickCounts = {
    all: document.querySelector('[data-quick-count="all"]'),
    inbox: document.querySelector('[data-quick-count="inbox"]')
};

const notify = (message, variant = 'info') => {
    if (typeof window.showToast === 'function') {
        window.showToast(message, variant);
    } else {
        alert(message);
    }
};

let emailCards = Array.from(document.querySelectorAll('.email-card'));
const searchInput = document.getElementById('searchInput');
let searchRaf = null;
let autoSyncTimer = null;

function applySearchFilter(query = '') {
    const normalized = (query || '').toLowerCase();
    emailCards.forEach(card => {
        if (!card || !card.isConnected) {
            return;
        }
        const subjectEl = card.querySelector('.email-card-subject, .email-subject');
        const senderEl = card.querySelector('.email-card-sender, .email-sender');
        const previewEl = card.querySelector('.email-card-preview, .email-preview');

        const subject = subjectEl ? subjectEl.textContent.toLowerCase() : '';
        const sender = senderEl ? senderEl.textContent.toLowerCase() : '';
        const preview = previewEl ? previewEl.textContent.toLowerCase() : '';

        if (subject.includes(normalized) || sender.includes(normalized) || preview.includes(normalized)) {
            card.style.display = '';
        } else {
            card.style.display = 'none';
        }
    });
}

if (searchInput) {
    applySearchFilter(searchInput.value || '');
    searchInput.addEventListener('input', (e) => {
        const value = e.target.value;
        if (searchRaf) {
            cancelAnimationFrame(searchRaf);
        }
        searchRaf = requestAnimationFrame(() => applySearchFilter(value));
    });
}

// Modal handling
const modal = document.getElementById('addLabelModal');
const addLabelBtn = document.getElementById('addLabelBtn');
const modalClose = document.querySelector('.modal-close');
const labelForm = document.getElementById('labelForm');
const dragState = {
    emailIds: [],
    cards: []
};

if (addLabelBtn) {
    addLabelBtn.addEventListener('click', () => {
        if (modal) {
            modal.style.display = 'flex';
        }
    });
}

if (modalClose) {
    modalClose.addEventListener('click', () => {
        if (modal) {
            modal.style.display = 'none';
        }
    });
}

window.addEventListener('click', (event) => {
    if (event.target === modal) {
        modal.style.display = 'none';
    }
});

Object.values(quickCounts).forEach(el => {
    if (el) {
        const initial = Number(el.textContent.trim());
        el.dataset.count = isNaN(initial) ? 0 : initial;
    }
});

function adjustQuickCount(key, delta) {
    if (!delta) return;
    const el = quickCounts[key];
    if (!el) return;
    const current = Number(el.dataset.count || el.textContent || 0);
    const next = Math.max(0, current + delta);
    el.dataset.count = next;
    el.textContent = next;
}

function getEmailCardById(emailId) {
    if (emailId === undefined || emailId === null) {
        return null;
    }
    const normalized = String(emailId);
    return document.querySelector(`.email-card[data-email-id="${normalized}"]`);
}

function countInboxCards(ids = []) {
    if (!ids?.length) {
        return 0;
    }
    return ids.reduce((count, identifier) => {
        const card = getEmailCardById(identifier);
        if (card && card.dataset.hasInbox === '1') {
            return count + 1;
        }
        return count;
    }, 0);
}

function reflowSelectionAfterRemoval() {
    setTimeout(() => {
        updateDeleteButtonState();
    }, 320);
}

function removeEmailsFromUI(ids = [], deletedCount) {
    if (!ids?.length) {
        return;
    }
    const uniqueIds = Array.from(new Set(ids.map(id => String(id))));
    if (!uniqueIds.length) {
        return;
    }
    const inboxRemovals = countInboxCards(uniqueIds);
    removeCardsByIds(uniqueIds);
    const totalDelta = Number.isFinite(deletedCount) ? deletedCount : uniqueIds.length;
    adjustQuickCount('all', -totalDelta);
    if (inboxRemovals) {
        adjustQuickCount('inbox', -inboxRemovals);
    }
    reflowSelectionAfterRemoval();
}

function removeCardsByIds(ids) {
    if (!ids?.length) return;
    const idSet = new Set(ids.map(id => String(id)));
    const targets = emailCards.filter(card => card && card.isConnected && idSet.has(card.dataset.emailId));
    targets.forEach(card => {
        card.classList.add('removing');
        setTimeout(() => card.remove(), 220);
    });
    if (!targets.length) {
        return;
    }
    setTimeout(() => {
        emailCards = emailCards.filter(card => card.isConnected);
        if (searchInput) {
            applySearchFilter(searchInput.value || '');
        }
    }, 260);
}

function clearDragState() {
    dragState.cards.forEach(card => card.classList.remove('dragging'));
    dragState.emailIds = [];
    dragState.cards = [];
}

// Create label
if (labelForm) {
    labelForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const name = document.getElementById('labelName').value;
        const color = document.getElementById('labelColor').value;
        const description = document.getElementById('labelDesc').value;

        try {
            const response = await fetch('/label/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, color, description })
            });

            const data = await response.json();
            if (data.success) {
                notify('Label created successfully!', 'success');
                location.reload();
            } else {
                notify(data.message || 'Failed to create label', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            notify('An error occurred', 'error');
        }
    });
}

// Sync emails with real-time updates
let currentEventSource = null;
const syncBtn = document.getElementById('syncBtn');
const syncModal = document.getElementById('syncModal');
const syncStatusIcon = document.getElementById('syncStatusIcon');
const syncStatusText = document.getElementById('syncStatusText');
const syncProgressFill = document.getElementById('syncProgressFill');
const syncProgressPercentage = document.getElementById('syncProgressPercentage');

const syncIconMap = {
    idle: '\u27F3',
    fetch: '\u23F3',
    process: '\u2699',
    sync: '\u21BB',
    clean: '\u267B',
    ai: '\u2728',
    success: '\u2705',
    error: '\u26A0'
};

function setSyncStatusIcon(state) {
    if (!syncStatusIcon) {
        return;
    }
    const glyph = syncIconMap[state] || syncIconMap.idle;
    syncStatusIcon.textContent = glyph;
}

function setIconButtonLoading(button, isLoading) {
    if (!button) {
        return;
    }
    const loading = Boolean(isLoading);
    button.classList.toggle('is-loading', loading);
    button.disabled = loading;
    if (loading) {
        button.setAttribute('aria-busy', 'true');
    } else {
        button.removeAttribute('aria-busy');
    }
}

let syncCompleted = false;

function finalizeSyncStream() {
    syncCompleted = true;
    if (currentEventSource) {
        currentEventSource.onmessage = null;
        currentEventSource.onerror = null;
        currentEventSource.close();
        currentEventSource = null;
    }
}

function startEmailSync(options = {}) {
    if (currentEventSource) {
        if (!options.silent) {
            notify('A sync is already running.', 'warning');
        }
        return;
    }
    clearAutoSyncTimer();

    const silent = Boolean(options.silent);
    syncCompleted = false;

    if (!silent) {
        if (syncModal) {
            syncModal.style.display = 'flex';
            syncModal.classList.add('syncing');
        }
        if (syncBtn) {
            syncBtn.disabled = true;
        }
        syncProgressFill.style.width = '0%';
        syncProgressPercentage.textContent = '0%';
        setSyncStatusIcon('idle');
        syncStatusText.textContent = 'Preparing sync...';
        syncStatusIcon?.classList.remove('complete');
    } else if (syncBtn) {
        syncBtn.disabled = true;
    }

    const params = new URLSearchParams();
    if (silent) {
        params.set('mode', 'background');
    }
    const url = `/email/sync${params.toString() ? `?${params.toString()}` : ''}`;
    currentEventSource = new EventSource(url);

    currentEventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.error) {
            finalizeSyncStream();
            if (!silent) {
                setSyncStatusIcon('error');
                notify(data.error, 'error');
            }
            closeSyncModal({ silent });
            return;
        }

        if (silent) {
            if (data.status === 'complete') {
                finalizeSyncStream();
                closeSyncModal({ silent: true });
                setTimeout(() => window.location.reload(), 500);
            }
            return;
        }

        switch (data.status) {
            case 'connecting':
                setSyncStatusIcon('idle');
                syncStatusText.textContent = data.message || 'Connecting to server...';
                syncProgressFill.style.width = '0%';
                syncProgressPercentage.textContent = '0%';
                break;
            case 'labels':
                setSyncStatusIcon('clean');
                syncStatusText.textContent = data.message || 'Refreshing Gmail labels...';
                break;
            case 'fetching':
                setSyncStatusIcon('fetch');
                syncStatusText.textContent = data.message || 'Fetching emails from server...';
                if (data.total && data.progress !== undefined) {
                    const percentage = Math.round((data.progress / data.total) * 100);
                    syncProgressFill.style.width = `${percentage}%`;
                    syncProgressPercentage.textContent = `${percentage}%`;
                }
                break;
            case 'processing':
                setSyncStatusIcon('process');
                syncStatusText.textContent = `Processing ${data.total} emails...`;
                syncProgressFill.style.width = '100%';
                syncProgressPercentage.textContent = '100%';
                break;
            case 'syncing':
                setSyncStatusIcon('sync');
                syncStatusText.textContent = `Syncing... (${data.synced || 0} new)`;
                if (data.total) {
                    const percentage = Math.round((data.progress / data.total) * 100);
                    syncProgressFill.style.width = `${percentage}%`;
                    syncProgressPercentage.textContent = `${percentage}%`;
                }
                break;
            case 'cleaning':
                setSyncStatusIcon('clean');
                syncStatusText.textContent = 'Cleaning up deleted emails...';
                syncProgressFill.style.width = '95%';
                syncProgressPercentage.textContent = '95%';
                break;
            case 'ai':
                setSyncStatusIcon('ai');
                syncStatusText.textContent = data.message || 'Adding AI suggestions...';
                syncProgressFill.style.width = '100%';
                syncProgressPercentage.textContent = '100%';
                break;
            case 'complete':
                finalizeSyncStream();
                setSyncStatusIcon('success');
                syncStatusIcon?.classList.add('complete');
                syncStatusText.textContent = data.message;
                syncProgressFill.style.width = '100%';
                syncProgressPercentage.textContent = '100%';
                setTimeout(() => {
                    closeSyncModal({ silent: false });
                    location.reload();
                }, 1500);
                break;
            default:
                break;
        }
    };

    currentEventSource.onerror = (error) => {
        if (syncCompleted) {
            closeSyncModal({ silent });
            return;
        }
        console.error('EventSource error:', error);
        if (!silent) {
            setSyncStatusIcon('error');
            const suffix = error && error.message ? `: ${error.message}` : '.';
            notify(`An error occurred during sync${suffix}`, 'error');
        }
        closeSyncModal({ silent });
    };
}

if (syncBtn) {
    syncBtn.addEventListener('click', () => startEmailSync({ silent: false }));
}

function closeSyncModal(options = {}) {
    finalizeSyncStream();
    if (!options.silent && syncModal) {
        syncModal.style.display = 'none';
        syncModal.classList.remove('syncing');
    }
    if (syncBtn) {
        syncBtn.disabled = false;
    }
    scheduleAutoSync();
}

function cancelSync() {
    if (confirm('Are you sure you want to cancel the sync? Progress will be saved up to this point.')) {
        closeSyncModal();
    }
}

// Prevent closing modal by clicking outside during sync
if (syncModal) {
    syncModal.addEventListener('click', (event) => {
        if (event.target === syncModal && syncModal.classList.contains('syncing')) {
            event.stopPropagation();
        }
    });
}

function clearAutoSyncTimer() {
    if (autoSyncTimer) {
        clearTimeout(autoSyncTimer);
        autoSyncTimer = null;
    }
}

function scheduleAutoSync(minutesOverride) {
    const minutes = Number(
        typeof minutesOverride === 'number'
            ? minutesOverride
            : window.MAILORG_AUTO_SYNC_MINUTES || 0
    );
    clearAutoSyncTimer();
    if (!minutes || minutes <= 0) {
        return;
    }
    const intervalMs = minutes * 60 * 1000;
    autoSyncTimer = setTimeout(() => startEmailSync({ silent: true }), intervalMs);
}

scheduleAutoSync();
window.addEventListener('focus', () => scheduleAutoSync());
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        scheduleAutoSync();
    }
});

const emailsGrid = document.getElementById('emailsGrid');
const layoutButtons = document.querySelectorAll('.layout-option');
const validLayouts = new Set(['1', '2', '3']);

function applyEmailLayout(layoutValue) {
    if (!emailsGrid) {
        return;
    }
    const layout = validLayouts.has(layoutValue) ? layoutValue : '3';
    emailsGrid.classList.remove('layout-1', 'layout-2', 'layout-3');
    emailsGrid.classList.add(`layout-${layout}`);
    layoutButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.layout === layout);
    });
}

const storedLayout = localStorage.getItem('emailLayout');
if (layoutButtons.length && emailsGrid) {
    applyEmailLayout(storedLayout);
    layoutButtons.forEach(button => {
        button.addEventListener('click', () => {
            const value = button.dataset.layout;
            if (!validLayouts.has(value)) {
                return;
            }
            localStorage.setItem('emailLayout', value);
            applyEmailLayout(value);
        });
    });
}

const deleteEmailsBtn = document.getElementById('deleteEmailsBtn');

function getSelectedEmailIds() {
    const checked = document.querySelectorAll('.email-select:checked');
    return Array.from(checked).map(cb => Number(cb.dataset.emailId));
}

function updateDeleteButtonState() {
    if (!deleteEmailsBtn) return;
    const count = getSelectedEmailIds().length;
    deleteEmailsBtn.disabled = count === 0;
    deleteEmailsBtn.textContent = count ? `Delete (${count})` : 'Delete Selected';
}

if (deleteEmailsBtn) {
    deleteEmailsBtn.addEventListener('click', async () => {
        const emailIds = getSelectedEmailIds();
        if (!emailIds.length) {
            return;
        }

        if (confirmDeleteEnabled && !confirm(`Delete ${emailIds.length} selected email${emailIds.length > 1 ? 's' : ''}? This cannot be undone.`)) {
            return;
        }

        deleteEmailsBtn.disabled = true;
        deleteEmailsBtn.textContent = 'Deleting...';

        try {
            const response = await fetch('/email/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email_ids: emailIds })
            });
            const data = await response.json();
            if (data.success) {
                const removedIds = data.deleted_ids || emailIds;
                removeEmailsFromUI(removedIds, data.deleted || removedIds.length);
                notify(`${data.deleted} email${data.deleted === 1 ? '' : 's'} deleted.`, 'success');
            } else {
                notify(data.message || 'Failed to delete emails.', 'error');
                deleteEmailsBtn.disabled = false;
                updateDeleteButtonState();
            }
        } catch (error) {
            console.error('Error deleting emails:', error);
            notify('An error occurred while deleting emails.', 'error');
            deleteEmailsBtn.disabled = false;
            updateDeleteButtonState();
        }
    });
}

// Prevent event bubbling on checkboxes
const emailCheckboxes = document.querySelectorAll('.email-select');
emailCheckboxes.forEach(checkbox => {
    checkbox.addEventListener('click', (e) => {
        e.stopPropagation();
    });

    checkbox.addEventListener('change', updateDeleteButtonState);
});

updateDeleteButtonState();

document.querySelectorAll('.ai-chip-action').forEach(chip => {
    chip.addEventListener('click', async (event) => {
        if (event.target.closest('.ai-remove-btn')) {
            return;
        }
        event.preventDefault();
        event.stopPropagation();

        const emailId = chip.dataset.emailId;
        if (!emailId) {
            return;
        }

        chip.classList.add('ai-chip-loading');

        try {
            const response = await fetch(`/email/${emailId}/ai-accept`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ label: chip.dataset.label })
            });
            const data = await response.json();
            if (data.success) {
                setTimeout(() => location.reload(), 500);
            } else {
                chip.classList.remove('ai-chip-loading');
                notify(data.message || 'Failed to apply AI labels.', 'error');
            }
        } catch (error) {
            chip.classList.remove('ai-chip-loading');
            console.error('Error applying AI labels:', error);
            notify('An error occurred while applying AI labels.', 'error');
        }
    });
});

document.querySelectorAll('.ai-remove-btn').forEach(button => {
    button.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const emailId = button.dataset.emailId;
        const label = button.dataset.label;
        if (!emailId || !label) {
            return;
        }
        button.disabled = true;
        try {
            const response = await fetch(`/email/${emailId}/ai-dismiss`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ label }),
                credentials: 'same-origin'
            });
            const data = await response.json();
            if (data.success) {
                button.closest('.ai-chip').remove();
            } else {
                notify(data.message || 'Failed to remove suggestion.', 'error');
                button.disabled = false;
            }
        } catch (error) {
            console.error('Error removing suggestion:', error);
            notify('An error occurred while removing the suggestion.', 'error');
            button.disabled = false;
        }
    });
});

document.querySelectorAll('.label-badge-remove').forEach(button => {
    button.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const emailId = button.dataset.emailId;
        const labelId = button.dataset.labelId;
        if (!emailId || !labelId) {
            return;
        }
        button.disabled = true;
        try {
            const response = await fetch(`/email/${emailId}/label/${labelId}`, {
                method: 'DELETE',
                credentials: 'same-origin'
            });
            const data = await response.json();
            if (data.success) {
                const badge = button.closest('.label-badge');
                if (badge) {
                    badge.remove();
                }
            } else {
                notify(data.message || 'Unable to remove label.', 'error');
                button.disabled = false;
            }
        } catch (error) {
            console.error('Error removing label:', error);
            notify('An error occurred while removing the label.', 'error');
            button.disabled = false;
        }
    });
});

function refreshLabelToggle(node) {
    if (!node) {
        return;
    }
    const row = node.firstElementChild;
    if (!row || !row.classList.contains('label-tree-row')) {
        return;
    }
    const toggle = row.querySelector('.label-tree-toggle');
    if (!toggle || toggle.classList.contains('placeholder') || toggle.tagName !== 'BUTTON') {
        return;
    }
    const collapsed = node.classList.contains('collapsed');
    toggle.textContent = collapsed ? '+' : '-';
    toggle.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
}

document.querySelectorAll('.label-tree-node').forEach(refreshLabelToggle);

document.querySelectorAll('.label-tree-toggle').forEach(toggle => {
    if (toggle.classList.contains('placeholder')) {
        return;
    }
    toggle.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        const node = toggle.closest('.label-tree-node');
        if (!node) return;
        node.classList.toggle('collapsed');
        refreshLabelToggle(node);
    });
});

document.querySelectorAll('.label-tree-row.active').forEach(row => {
    let node = row.closest('.label-tree-node');
    while (node) {
        node.classList.remove('collapsed');
        refreshLabelToggle(node);
        node = node.parentElement.closest('.label-tree-node');
    }
});

function clearLabelDropHighlights() {
    document.querySelectorAll('.label-tree-row.drop-target').forEach(row => {
        row.classList.remove('drop-target');
    });
}

function shouldRemoveAfterMoveForEmail(targetLabelId, removedInbox) {
    if (currentFilter.forceAll) {
        return false;
    }
    if (currentFilter.selectedLabel) {
        return String(currentFilter.selectedLabel) !== String(targetLabelId);
    }
    if (removedInbox && currentFilter.inboxLabel) {
        return true;
    }
    return false;
}

async function moveEmailsToLabel(emailIds, labelId, labelName, removeInbox = false) {
    if (!emailIds?.length || !labelId) {
        return;
    }
    const targetLabelId = Number(labelId);
    if (Number.isNaN(targetLabelId)) {
        return;
    }
    const uniqueIds = Array.from(new Set(emailIds.map(Number))).filter(id => !Number.isNaN(id));
    if (!uniqueIds.length) {
        return;
    }
    try {
        const response = await fetch('/email/move', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label_id: targetLabelId, email_ids: uniqueIds, remove_inbox: removeInbox }),
            credentials: 'same-origin'
        });
        const data = await response.json();
        if (data.success) {
            notify(`Moved email${uniqueIds.length > 1 ? 's' : ''} to ${labelName}.`, 'success');
            const removedSet = new Set((data.removed_inbox_ids || []).map(id => String(id)));
            const removable = [];
            (data.moved_ids || []).forEach(id => {
                const removedInbox = removedSet.has(String(id));
                if (shouldRemoveAfterMoveForEmail(targetLabelId, removedInbox)) {
                    removable.push(Number(id));
                }
            });
            removeCardsByIds(removable);
            if (removedSet.size) {
                adjustQuickCount('inbox', -removedSet.size);
            }
        } else {
            notify(data.message || 'Unable to move email.', 'error');
        }
    } catch (error) {
        console.error('Error moving email:', error);
        notify('An error occurred while moving the email.', 'error');
    }
}

function setupDragAndDrop() {
    emailCards.forEach(card => {
        card.addEventListener('dragstart', (event) => {
            const emailId = Number(card.dataset.emailId);
            const selectedIds = getSelectedEmailIds();
            const dragIds = selectedIds.includes(emailId) ? selectedIds : [emailId];
            dragState.emailIds = dragIds;
            dragState.cards = emailCards.filter(c => dragIds.includes(Number(c.dataset.emailId)));
            if (!dragState.cards.length) {
                dragState.cards = [card];
            }
            dragState.cards.forEach(c => c.classList.add('dragging'));
            if (event.dataTransfer) {
                event.dataTransfer.effectAllowed = 'move';
                event.dataTransfer.setData('text/plain', dragIds.join(','));
            }
        });

        card.addEventListener('dragend', () => {
            clearDragState();
            clearLabelDropHighlights();
        });
    });

    const labelRows = document.querySelectorAll('.label-tree-row[data-label-id]');
    labelRows.forEach(row => {
        row.addEventListener('dragover', (event) => {
            if (!dragState.emailIds.length) {
                return;
            }
            event.preventDefault();
            row.classList.add('drop-target');
            if (event.dataTransfer) {
                event.dataTransfer.dropEffect = 'move';
            }
        });

        row.addEventListener('dragleave', () => {
            row.classList.remove('drop-target');
        });

        row.addEventListener('drop', async (event) => {
            if (!dragState.emailIds.length) {
                return;
            }
            event.preventDefault();
            clearLabelDropHighlights();
            const labelId = row.dataset.labelId;
            const labelName = row.dataset.labelName || 'label';
            try {
            await moveEmailsToLabel(dragState.emailIds, labelId, labelName, true);
            } finally {
                clearDragState();
            }
        });
    });
}

document.querySelectorAll('.email-delete-btn').forEach(button => {
    button.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const emailId = button.dataset.emailId;
        if (!emailId) {
            return;
        }
        if (confirmDeleteEnabled && !confirm('Delete this email? This action cannot be undone.')) {
            return;
        }
        setIconButtonLoading(button, true);
        try {
            const response = await fetch('/email/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email_ids: [Number(emailId)] })
            });
            const data = await response.json();
            if (data.success) {
                setIconButtonLoading(button, false);
                const removedIds = data.deleted_ids || [emailId];
                removeEmailsFromUI(removedIds, data.deleted || removedIds.length);
                notify(data.message || 'Email deleted.', 'success');
            } else {
                notify(data.message || 'Failed to delete email.', 'error');
                setIconButtonLoading(button, false);
            }
        } catch (error) {
            console.error('Error deleting email:', error);
            notify('An error occurred while deleting the email.', 'error');
            setIconButtonLoading(button, false);
        }
    });
});

// Delete label function
async function deleteLabel(event, labelId, labelName) {
    event.preventDefault();
    event.stopPropagation();

    if (!confirm(`Are you sure you want to delete the label "${labelName}"? This will remove it from all emails.`)) {
        return;
    }

    try {
        const response = await fetch(`/label/${labelId}`, {
            method: 'DELETE'
        });

        const data = await response.json();
        if (data.success) {
            location.reload();
        } else {
            notify(data.message || 'Failed to delete label', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        notify('An error occurred while deleting the label', 'error');
    }
}

setupDragAndDrop();
