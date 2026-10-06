# Security findings

Severity reflects exploitability and impact in VulnTracker, not just a scanner score.

| Finding | Source / type | Severity | Business impact | Location | Status |
|---|---|---:|---|---|---|
| SQL injection in search | Manual review / SAST | Critical | An attacker could read or alter scan data, including customer vulnerability details. | Starter `app/database.py` | Fixed with bound parameters and owner scoping |
| Cross-tenant scan access | Manual review | High | An authenticated user could access another team's finding by changing an ID. | Starter `app/main.py` | Fixed with owner-scoped queries |
| JWT accepted `none` algorithm | Manual review / SAST | High | Forged tokens could impersonate any user. | Starter `app/auth.py` | Fixed by allowing only HS256 |
| Secrets committed in source | SCA/manual | High | Repository readers could use credentials against production dependencies. | Starter config and notify config | Fixed for Python config; notify remains deferred |
| Share tokens stored in plaintext | Manual review | High | Database compromise would immediately expose active public reports. | New share feature | Fixed: only SHA-256 token hashes are persisted |
| Unauthenticated webhook administration / SSRF | Manual review | High | Attackers could register internal URLs and make the service send requests into private networks. | Starter `notify/` | Deferred; isolate service and add auth/URL allowlist |
| Error responses disclosed traceback and request URL | Manual review | Medium | Internal paths and implementation details would aid follow-on attacks. | Starter `app/main.py` | Fixed with generic response |
| Over-permissive CORS reflection | Manual review | Medium | A malicious site could make credentialed browser requests. | Starter `app/main.py` | Fixed: explicit allowlist only when configured |

## Scan execution

The required report files are checked into `reports/`. They record tool, command, and result metadata so a reviewer can reproduce the scans. In CI, these should be generated with pinned tool versions and uploaded as artifacts. The code review findings above include manual review because automated tools do not reliably detect authorization flaws.
