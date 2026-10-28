# ScamEye 🛡️
### AI-Powered Scam Message Detection

**[🚀 Live Demo](https://scameye-multilingual-message-scam.onrender.com) · Source Code: This GitHub Repository**

ScamEye is an AI-powered web application that analyzes suspicious messages and helps users identify potential scams, phishing attempts, and fraudulent communications using AI-based analysis and rule-based detection.

Users can submit message text or upload screenshots for analysis, review safety assessments, and access their personal scan history through an authenticated account.

## ✨ Features

- **AI-Powered Scam Detection:** Analyze messages using the Google Gemini API alongside rule-based detection.
- **Screenshot Analysis:** Upload screenshots to extract and analyze message content.
- **Multilingual Support:** Analyze messages in supported languages.
- **User Authentication:** Email/password registration, email verification, and password recovery using Supabase Auth.
- **Scan History:** Store and revisit previous scan results associated with the authenticated user.
- **Safety Assessment:** Provide analysis results to help users evaluate suspicious communications.
- **Responsive UI:** Dark-themed interface designed for desktop and mobile screens.
- **Cloud Deployment:** Hosted on Render.

## 🧰 Tech Stack

| Category | Technologies |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| AI Integration | Google Gemini API |
| Database | PostgreSQL |
| Authentication and Backend Services | Supabase |
| Deployment | Render |
| Version Control | Git, GitHub |

## 🏗️ Architecture

1. A user submits message text or a screenshot through the web interface.
2. The Flask backend processes the request and uses AI analysis and rule-based detection to assess potential scam indicators.
3. Protected operations validate the user's Supabase access token.
4. Scan results can be stored in PostgreSQL and associated with the authenticated user's ID.
5. Authenticated users can access their own scan history.

Supabase Auth handles account credentials, email verification, and password recovery.

## 📁 Project Structure

```text
ScamEye/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── templates/
│   └── index.html
├── static/
│   ├── script.js
│   └── style.css
└── supabase/
    └── schema.sql
```

## ⚙️ Environment Variables

Configure these variables in your local environment or deployment platform:

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google Gemini API key |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_ANON_KEY` | Supabase public/anonymous key |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-side privileged key |

Use `.env.example` as a reference for configuration. Store real credentials in your local `.env` file or your hosting provider's environment settings. Never commit secrets to GitHub.

## 🚀 Run Locally

**1. Clone the repository**

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ScamEye
```

**2. Create and activate a virtual environment**

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Configure environment variables**

Create a `.env` file based on `.env.example` and add the required credentials.

**5. Configure Supabase**

Run `supabase/schema.sql` in the Supabase SQL Editor. Configure email authentication, email verification, password recovery, and the appropriate redirect URLs.

**6. Start the application**

```bash
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

## ☁️ Deployment

ScamEye is hosted on Render and can be deployed from a connected GitHub repository.

1. Connect the repository to a Render Web Service.
2. Configure the Python environment and dependency installation.
3. Add the required environment variables in the Render dashboard.
4. Configure Supabase authentication redirect URLs for the production domain.
5. Set the appropriate production start command for the Flask application.
6. Deploy and inspect the application logs to verify successful startup.

**Live application:** [https://scameye-multilingual-message-scam.onrender.com](https://scameye-multilingual-message-scam.onrender.com)

## 🔐 Security Considerations

- Supabase Auth manages user authentication and password recovery.
- Protected endpoints should validate access tokens server-side.
- Database queries must enforce user-level access restrictions.
- Privileged Supabase keys must remain server-side.
- Scan history may contain sensitive information; handle storage, retention, and deletion responsibly.

## ⚠️ Disclaimer

ScamEye is an assistive scam-detection tool. Its results may produce false positives or miss fraudulent messages. Always verify suspicious communications through official websites, applications, or trusted contact channels. Never share passwords, OTPs, or banking credentials in response to suspicious messages.

## 👨‍💻 Author

Developed as a project exploring AI integration, web application development, authentication, database management, and cloud deployment.