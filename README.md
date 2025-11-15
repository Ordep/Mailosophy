# Mailosophy - Email Organization Web Application

A modern web application for organizing emails with AI-powered labeling and categorization.

## Features

**Email Management**
- Import emails directly from Gmail using the Gmail API
- View email details with full formatting support
- Search and filter emails
- Mark emails as read/starred

**Intelligent Labeling**
- Pre-defined labels: Work, Important, Personal, Newsletter, Spam, Social
- AI-powered automatic label suggestions based on email content
- Create custom labels with custom colors
- Assign multiple labels per email

**User Accounts**
- Secure user authentication
- Google Workspace linking per user
- Personal email organization

**Modern Interface**
- Responsive dashboard design
- Sidebar navigation
- Email preview and detail views
- Intuitive label management

**AI Suggestions**
- Generate OpenAI-powered label suggestions per email
- Highlight emails with pending suggestions on the dashboard
- Accept suggestions to apply labels and push them back to Gmail

## Tech Stack

- **Backend**: Python with Flask
- **Database**: SQLAlchemy (SQLite)
- **Frontend**: HTML, CSS, JavaScript
- **AI**: Scikit-learn for email classification
- **Email**: Gmail API integration

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup

1. Clone the repository:
```bash
cd Mailosophy
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
cp .env.example .env
```

Edit `.env` file with your settings:
```
FLASK_APP=main.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///Mailosophy.db
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
OPENAI_API_KEY=your-openai-api-key-here
```

### Google OAuth Setup

To enable Google authentication:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the following APIs:
   - Gmail API
4. Create OAuth 2.0 credentials:
   - Application type: Web application
   - Authorized redirect URIs: `http://localhost:5000/auth/google/callback`
5. Copy the Client ID and Client Secret to your `.env` file

5. Initialize database:
```bash
python main.py
```

## Running the Application

```bash
python main.py
```

The application will be available at `http://localhost:5000`.

## Usage

### Creating an Account
1. Click "Register" on the login page
2. Fill in your details
3. Click "Register"

### Syncing Emails
1. Click the **Sync Emails** button in the dashboard
2. If prompted, connect and authorize your Google account
3. Gmail messages will stream in and become available for AI suggestions or manual labeling
4. Enable auto sync in **Settings → Preferences & Automation** to trigger background syncs every _n_ minutes (when the dashboard is open)

### Managing Labels
1. View all labels in the left sidebar
2. Click "+ New Label" to create custom labels
3. Click on a label to view emails with that label
4. On the email detail page, add/remove labels as needed

### AI Suggestions
1. Open any email from the dashboard
2. Click **Generate Suggestions** to have OpenAI analyze the message
3. Suggested labels appear both on the detail page and as highlights on the dashboard
4. Click **Keep Tagging** to apply the labels; if your account is linked to Gmail, they sync back automatically

### Finding Emails
1. Use the search box to search by sender, subject, or content
2. Click on labels to filter emails
3. Use pagination to browse through emails

## Project Structure

```
Mailosophy/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes.py                # API routes and views
│   ├── models/
│   │   ├── user.py              # User model
│   │   └── email.py             # Email and Label models
│   ├── utils/
│   │   └── ai_labeler.py         # AI-based email classification
│   ├── templates/
│   │   ├── base.html            # Base template
│   │   ├── login.html           # Login page
│   │   ├── register.html        # Registration page
│   │   ├── dashboard.html       # Main dashboard
│   │   └── email_detail.html    # Email detail view
│   └── static/
│       ├── css/
│       │   └── style.css        # Main stylesheet
│       └── js/
│           ├── main.js          # Main JavaScript
│           └── dashboard.js     # Dashboard functionality
├── config/                      # Configuration files
├── main.py                      # Application entry point
├── requirements.txt             # Python dependencies
└── .env.example                 # Environment variables template
```

## Features Coming Soon

- 📎 Attachment support
- 📧 Email reply/forward
- 🔔 Notifications
- 📊 Email analytics
- 🔍 Advanced search filters
- 🤖 Custom AI model training
- 📱 Mobile app

## API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/logout` - User logout

### Emails
- `POST /email/sync` - Sync emails from Gmail
- `GET /email/<id>` - View email details
- `POST /email/<id>/label` - Add label to email
- `DELETE /email/<id>/label/<label_id>` - Remove label from email

### Labels
- `POST /label/create` - Create new label
- `GET /label/all` - Get all labels
- `DELETE /label/<id>` - Delete label

## Troubleshooting

### "Email sync not working"
- Check internet connection
- Ensure your Google account is connected (Dashboard banner shows status)
- Re-run Google OAuth if tokens expired
- Check application logs

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is open source and available under the MIT License.

## Support

For issues, questions, or suggestions, please open an issue on GitHub.
