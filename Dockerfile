# SPECTER X — single-stage build, no compilation step (CONTRACTS §7: no npm).
FROM python:3.12-slim

WORKDIR /srv/specter-x

# Datasets are part of the demo (synthetic, generated at repo time —
# datasets/provenance.json). Copy everything, then prune dev-only paths.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ backend/
COPY datasets/ datasets/
COPY frontend/ frontend/

# Non-root runtime. /data pre-created so the named volume inherits this
# ownership (SQLite must be writable there).
RUN useradd --system --uid 10001 specter \
    && mkdir -p /data && chown -R specter:specter /srv/specter-x /data
USER specter

ENV DATABASE_URL=sqlite:////data/specter.db
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

# backend/ is not a package on sys.path; --app-dir fixes the import root.
CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
