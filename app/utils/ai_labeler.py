from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline


class AILabeler:
    def __init__(self):
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=1000, stop_words='english')),
            ('classifier', MultinomialNB())
        ])
        self.is_trained = False
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
        """Suggest labels for an email based on content"""
        if available_labels is None:
            available_labels = list(self.predefined_labels.keys())

        text_lower = email_text.lower()
        suggested = []
        scores = {}

        # Keyword-based matching
        for label, config in self.predefined_labels.items():
            if label not in available_labels:
                continue

            score = 0
            for keyword in config['keywords']:
                if keyword in text_lower:
                    score += 1

            if score > 0:
                scores[label] = score

        # Sort by score and return top 3
        sorted_labels = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [label for label, _ in sorted_labels[:3]]

    def train(self, emails_data, labels_data):
        """Train the AI model with email data"""
        try:
            if len(emails_data) < 2:
                self.is_trained = False
                return False

            self.model.fit(emails_data, labels_data)
            self.is_trained = True
            return True
        except Exception as e:
            print(f"Training error: {e}")
            return False

    def predict(self, email_text):
        """Predict label for email"""
        if not self.is_trained:
            return self.suggest_labels(email_text)

        try:
            prediction = self.model.predict([email_text])[0]
            return prediction
        except:
            return self.suggest_labels(email_text)

    def get_predefined_labels(self):
        """Get all predefined labels"""
        return self.predefined_labels
