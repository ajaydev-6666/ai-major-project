# ScamShield AI

AI-powered scam and fraud detection platform built as a B.Tech CSE major project.

## Features

- Message/text scam detection using TF-IDF + Logistic Regression
- URL risk analysis
- Scam category detection
- Risk score and explainable reasons
- User search history
- User feedback submission
- Admin dashboard and feedback validation queue
- Animated Message / URL scanner selection
- Admin password visibility eye icon
- SQLite storage for local development
- Windows `run.bat` launcher

## Project Structure

```text
ScamShield_AI/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── run.bat
├── run_admin.bat
├── templates/
│   ├── index.html
│   ├── admin_login.html
│   └── admin.html
└── static/
    └── style.css
```

## Run Locally

### Windows

Double-click `run.bat`.

Or from Command Prompt:

```bat
run.bat
```

The launcher creates a local `.venv`, installs dependencies, starts Flask, and opens the application.

### Manual setup

```bash
python -m venv .venv
```

Windows:

```bat
.venv\Scripts\activate
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
python app.py
```

Open `http://127.0.0.1:5000` in a browser.

## Admin

Open:

`http://127.0.0.1:5000/admin/login`

For local demonstration, the application has a default admin account. For deployment, configure the admin credentials through environment variables and do not commit passwords to Git.

## Data Storage

The application uses SQLite for local development. The database is generated at runtime and is intentionally excluded from Git through `.gitignore`.

This means each fresh clone starts with a new local database.

## GitHub Upload

From the project directory:

```bash
git init
git add .
git commit -m "Initial ScamShield AI project"
git branch -M main
git remote add origin YOUR_GITHUB_REPOSITORY_URL
git push -u origin main
```

Do **not** commit:

- `.venv/`
- `.env`
- SQLite database files
- Python cache files
- IDE settings

## Important Deployment Note

The built-in ML dataset is a small demonstration dataset intended for the academic prototype. It should not be treated as a production-grade fraud intelligence system without a larger validated dataset, security hardening, authentication improvements, and additional testing.
