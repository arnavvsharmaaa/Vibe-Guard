# Vibe Guard backend: FastAPI + Semgrep + Bandit (Phase 14a demo image).
# Build from backend/:  docker build -t vibe-guard-api .
#
# glibc-based image: Semgrep's Linux wheel ships a native semgrep-core binary tagged manylinux_2_34
# (glibc >= 2.34). python:3.14-slim is Debian with glibc 2.41. Every runtime dependency installs from a wheel,
# so no compiler is needed.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Scanners run with PATH set to their own directory only (scanners.py). semgrep-core runs `uname -s` at startup and
# exits 2 without it, so uname alone is linked into that directory; nothing else from /usr/bin is exposed.
RUN ln -s /usr/bin/uname /usr/local/bin/uname

# Unprivileged user. It needs a home directory because Semgrep writes ~/.semgrep.
# /app/data holds the SQLite database and the scan directories; it is the only writable app path.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /app/data/uploads \
    && chown -R app:app /app/data

# Runtime code only: no tests, .env, database, uploads or virtual environment (see .dockerignore).
COPY main.py database.py scanners.py normalization.py scoring.py ai_analysis.py ./
COPY semgrep_rules/ semgrep_rules/

ENV HOST=0.0.0.0 \
    PORT=8000 \
    DATABASE_URL=sqlite:////app/data/vibe_guard.db \
    UPLOAD_DIR=/app/data/uploads

USER app
EXPOSE 8000

# Local Docker health check (Render uses its own healthCheckPath). If ALLOWED_HOSTS is set, include 127.0.0.1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ['PORT'] + '/api/health', timeout=4)"]

# One worker: the scan rate limiter and scan slots are in memory, and SQLite has a single writer. No --reload.
# uvicorn does not rewrite the client address from proxy headers; the app reads X-Forwarded-For itself, only
# when TRUSTED_PROXY_HOPS is set. PORT is provided by Render.
CMD ["sh", "-c", "exec uvicorn main:app --host \"$HOST\" --port \"$PORT\" --workers 1 --no-proxy-headers --no-server-header"]
