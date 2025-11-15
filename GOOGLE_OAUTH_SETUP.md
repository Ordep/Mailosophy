# Google OAuth Setup Guide for Mailosophy

This guide will help you set up Google OAuth authentication for the Mailosophy application.

## Why Google OAuth?

Google OAuth provides:
- **Secure authentication** without storing passwords
- **Direct Gmail access** via Gmail API
- **Automatic IMAP configuration** for Gmail accounts
- **Better security** with token-based authentication

## Step-by-Step Setup

### 1. Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown at the top
3. Click "NEW PROJECT"
4. Enter a project name (e.g., "Mailosophy")
5. Click "CREATE"
6. Wait for the project to be created

### 2. Enable Required APIs

1. In the Google Cloud Console, go to the **APIs & Services** page
2. Click **Enable APIs and Services**
3. Search for and enable these APIs:
   - **Gmail API**: Enables reading and managing Gmail
   - **Google+ API**: Provides user profile information
   - **Google Identity**: For OAuth 2.0

To enable each API:
- Search for the API name
- Click on it
- Click the "ENABLE" button
- Wait for it to be enabled

### 3. Create OAuth 2.0 Credentials

1. Go to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **OAuth 2.0 Client IDs**
3. If prompted, configure the OAuth consent screen first:
   - Choose **External** user type
   - Fill in the required information:
     - App name: "Mailosophy"
     - User support email: Your email
     - Developer contact: Your email
   - Add scopes:
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/gmail.modify`
     - `https://www.googleapis.com/auth/userinfo.profile`
     - `https://www.googleapis.com/auth/userinfo.email`
   - Continue through the wizard

4. After setting up consent screen, create credentials again:
   - Select **Web application** as application type
   - Name: "Mailosophy Web Client"
   - Authorized redirect URIs: Add these:
     - `http://localhost:5000/auth/google/callback` (Development)
     - `http://127.0.0.1:5000/auth/google/callback` (Alternative)
     - `https://yourdomain.com/auth/google/callback` (Production)
   - Click "CREATE"

### 4. Copy Credentials to .env

1. The credentials page will display your OAuth 2.0 Client:
   - Click the download icon or click on the credentials
   - You'll see:
     - **Client ID**
     - **Client Secret**

2. Update your `.env` file:
```bash
GOOGLE_CLIENT_ID=YOUR_CLIENT_ID_HERE
GOOGLE_CLIENT_SECRET=YOUR_CLIENT_SECRET_HERE
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
```

Replace:
- `YOUR_CLIENT_ID_HERE` with your actual Client ID
- `YOUR_CLIENT_SECRET_HERE` with your actual Client Secret

### 5. Install Dependencies

Make sure you have the required Google OAuth libraries:

```bash
pip install -r requirements.txt
```

This includes:
- `google-auth-oauthlib`
- `google-api-python-client`
- `PyJWT`

### 6. Test the Setup

1. Start the application:
```bash
python main.py
```

2. Navigate to `http://localhost:5000`

3. Click **"Continue with Google"** on the login page

4. You should be redirected to Google's login page

5. Sign in with your Google account

6. Grant permissions when prompted

7. You should be redirected back to Mailosophy and logged in

## Features After Google Auth Setup

✅ **Automatic Gmail Connection**
- Your Gmail account is automatically connected
- No need to manually configure IMAP credentials

✅ **Gmail API Access**
- Read emails directly from Gmail API
- Better email syncing
- More reliable than IMAP

✅ **Secure Token Management**
- Tokens are stored securely in the database
- Automatic token refresh
- No passwords stored

✅ **Profile Information**
- Your Google profile picture and name are used
- Better personalization

## Troubleshooting

### "Redirect URI Mismatch"
**Problem**: Error about redirect URI not matching

**Solution**:
1. Verify your `.env` file has the correct `GOOGLE_REDIRECT_URI`
2. Make sure this URI is registered in Google Cloud Console
3. Ensure the protocol (http vs https) matches exactly

### "Client ID not found"
**Problem**: App crashes because GOOGLE_CLIENT_ID is not set

**Solution**:
1. Check your `.env` file
2. Make sure you've copied the Client ID correctly
3. Restart the application after updating `.env`

### "Invalid grant"
**Problem**: Token refresh fails

**Solution**:
1. Clear browser cookies and try logging in again
2. Check that your credentials are correct in Google Cloud Console
3. Make sure the app isn't using an expired refresh token

### "Insufficient permissions"
**Problem**: User gets permission error

**Solution**:
1. Go to Google Cloud Console
2. Check that all required APIs are enabled
3. Verify OAuth consent screen is properly configured
4. Ensure all required scopes are added

## Production Deployment

When deploying to production:

1. **Update Redirect URI**:
   - Change `GOOGLE_REDIRECT_URI` to your domain:
     ```
     GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
     ```

2. **Update Google Cloud Console**:
   - Add your production redirect URI to authorized URIs

3. **Set Environment Variables**:
   - Use environment variables instead of `.env` file
   - Never commit `.env` to version control

4. **Enable HTTPS**:
   - Google OAuth requires HTTPS in production
   - Use a service like Let's Encrypt for free SSL certificates

## Alternative: Using Service Account (Advanced)

For server-to-server communication, you can use a Service Account:

1. In Google Cloud Console > Credentials
2. Create a new Service Account
3. Download the JSON key file
4. Use it in the app for Gmail API access

## Support

For issues or questions:
- Check [Google OAuth Documentation](https://developers.google.com/identity/protocols/oauth2)
- Review [Gmail API Documentation](https://developers.google.com/gmail/api)
- Check application logs for detailed error messages

## Security Notes

⚠️ **Important Security Information**

- Never commit `.env` file to version control
- Keep `GOOGLE_CLIENT_SECRET` confidential
- Use HTTPS in production
- Regularly review connected applications in your Google Account
- Tokens are stored encrypted in the database
- You can revoke app access anytime in Google Account settings
