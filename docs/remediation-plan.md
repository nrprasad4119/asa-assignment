# Remediation plan

## Deferred work

1. **Notification service administration and SSRF (High).** The starter service has no authentication on webhook registration or `/notify`, and accepts arbitrary destinations. Residual risk is unauthorized registrations and requests to cloud metadata/internal services. Estimated effort: 1–2 days for service authentication, a destination allowlist with DNS/IP validation, request signing, and integration tests. Compensating controls: keep it on a private network, expose only the API-to-notify route, and apply egress NetworkPolicies.
2. **Node.js committed service key (High).** Moving it to environment/secret-manager injection is straightforward but needs a deployment secret and rotation procedure. Estimated effort: half a day. Until then, treat the value as compromised and rotate it before production.
3. **SQLite for production (Medium).** SQLite limits concurrency and complicates backups. Estimated effort: 1–2 days to migrate to PostgreSQL, add migrations, encrypted backups, and restore tests. Compensating controls: single-replica prototype use only and restricted persistent storage.

## Completed

The application now uses parameterized SQL, tenant ownership checks, strict JWT algorithm validation, non-disclosing errors, validated input, and hashed random share tokens. Share links expire after 24 hours and optional passwords use bcrypt.
