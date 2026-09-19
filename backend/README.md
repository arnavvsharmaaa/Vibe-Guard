# Vibe Guard Backend

FastAPI backend for Vibe Guard - AI-Powered Secure Code Auditor.

## Setup & Running (Phase 1)

### 1. Create and Activate Virtual Environment
\\\ash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
\\\

### 2. Install Dependencies
\\\ash
pip install -r requirements.txt
\\\

### 3. Run Development Server
\\\ash
python main.py
# or
uvicorn main:app --reload --host 0.0.0.0 --port 8000
\\\

### 4. Endpoints
- Health check: \GET http://localhost:8000/api/health\
- Interactive API Docs: \http://localhost:8000/docs\
"@

Set-Content -Path "backend\.gitignore" -Value @"
venv/
.venv/
__pycache__/
*.py[cod]
.env
