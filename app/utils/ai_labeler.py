class AILabeler:
    """Lightweight keyword-based label suggester plus predefined color map."""

    def __init__(self):
        self.predefined_labels = {
            'work': {
                'keywords': ['meeting', 'deadline', 'project', 'task', 'report', 'urgent'],
                'color': '#FF6B6B'
            },
            'important': {
                'keywords': ['important', 'urgent', 'asap', 'critical', 'priority'],
                'color': '#FFD93D'
            },
            'personal': {
                'keywords': ['hi', 'hey', 'friend', 'family', 'weekend', 'fun'],
                'color': '#6BCB77'
            },
            'newsletter': {
                'keywords': ['newsletter', 'subscription', 'update', 'weekly', 'digest'],
                'color': '#4D96FF'
            },
            'spam': {
                'keywords': ['unsubscribe', 'viagra', 'click here', 'limited time', 'free'],
                'color': '#808080'
            },
            'social': {
                'keywords': ['notification', 'followed', 'liked', 'shared', 'commented'],
                'color': '#FF6B9D'
            }
        }

    def suggest_labels(self, email_text, available_labels=None):
        """Guess labels using simple keyword counting."""
        if not email_text:
            return []

        if available_labels is None:
            available_labels = list(self.predefined_labels.keys())

        text_lower = email_text.lower()
        scores = {}

        for label, config in self.predefined_labels.items():
            if label not in available_labels:
                continue

            score = sum(1 for keyword in config['keywords'] if keyword in text_lower)
            if score > 0:
                scores[label] = score

        return [label for label, _ in sorted(scores.items(), key=lambda item: item[1], reverse=True)[:3]]

    def get_predefined_labels(self):
        return self.predefined_labels
