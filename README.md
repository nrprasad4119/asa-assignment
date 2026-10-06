# VulnTracker security assignment

A hardened FastAPI vulnerability-tracking prototype with a 24-hour shared-report link feature.

## Local development

Python 3.11 is required.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
cd app && uvicorn main:app --reload
```

The API is available at `http://localhost:8000`; docs are at `/docs`. Set `ALLOWED_ORIGINS` to a comma-separated allowlist when a browser client is used. Share links contain a random bearer token, only its SHA-256 hash is stored, and links expire after 24 hours. Passwords are never logged or returned.

## Tests

```bash
pytest tests/ -v
cd notify && npm install && npm test
```

## Container

```bash
docker build -t vulntracker-api:1.1.0 .
docker run --rm -p 8000:8000 \
  -e SECRET_KEY="replace-with-a-secret-manager-value" \
  -e DATABASE_URL="sqlite:////tmp/vulntracker.db" vulntracker-api:1.1.0
```

The image uses a pinned Python base, a non-root user, a health check, and no embedded credentials. For production, inject `SECRET_KEY` and database configuration through a secret manager.

## Kubernetes/Helm

`helm/vulntracker` includes a Deployment, Service, NetworkPolicy, probes, resource limits, a read-only filesystem, dropped Linux capabilities, and references to an externally-created Kubernetes Secret named `vulntracker-secrets` with `secret-key` and `database-url` keys.

```bash
helm upgrade --install vulntracker helm/vulntracker \
  --set image.repository=your-registry/vulntracker-api
```

## Security work

See `docs/findings.md`, `docs/remediation-plan.md`, and `docs/executive-summary.md`. Raw scan report files are under `reports/`; regenerate them in CI using Bandit, pip-audit, Trivy, and Checkov after building/rendering the artifacts.
