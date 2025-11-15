// Main application JavaScript
console.log('Mailosophy application loaded');

(function () {
    const rootId = 'toast-root';

    function ensureToastRoot() {
        let root = document.getElementById(rootId);
        if (!root) {
            root = document.createElement('div');
            root.id = rootId;
            document.body.appendChild(root);
        }
        return root;
    }

    window.showToast = function (message, variant = 'info', timeoutMs = 4000) {
        try {
            const root = ensureToastRoot();
            const toast = document.createElement('div');
            toast.className = `toast toast-${variant}`;
            toast.textContent = message;
            root.appendChild(toast);

            requestAnimationFrame(() => {
                toast.classList.add('visible');
            });

            setTimeout(() => {
                toast.classList.remove('visible');
                setTimeout(() => toast.remove(), 250);
            }, timeoutMs);
        } catch (error) {
            console.error('Toast failed, falling back to alert:', error);
            alert(message);
        }
    };
})();
