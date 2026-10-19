# AegisAuth Progress Plan

## Goal

Host an educational Zero-Trust gateway where visitors can try browser-risk simulations, inspect real blocked-attempt metrics, and optionally use real human OIDC and M2M OAuth flows.

## Current Progress

- **Complete:** FastAPI scaffold, development-only demo login, OIDC Authorization Code + PKCE routes, signed browser session, logout, and protected welcome page.
- **Complete:** M2M JWT/JWKS validation, issuer/audience/expiry/scope checks, protected API endpoint, and Redis sliding-window rate limits.
- **Complete:** Single-page Sign In, Dashboard, and Try Simulation tabs. Single evaluations show scores/reasons without writes. Bounded batches (3–25) persist each virtual result as simulation-only events and update separate totals/history without affecting real blocked-attempt counts.
- **Complete:** SQL event persistence for actual blocked honeypot/high-risk login attempts, dashboard totals, and 24-hour hourly history. Redis remains the fast rate-limit store. Local default is SQLite; Render blueprint provisions Postgres.
- **Complete:** Local Keycloak Compose and realm/client seed configuration plus setup documentation. Demo client credentials are local-only.
- **Complete:** Ten fictional F1-themed Keycloak test users with distinct local-only passwords, plus generic `demo` and M2M service accounts. They are not official driver accounts.
- **Complete:** Autofill-safe heuristic handling: missing interaction is weak evidence and cannot block by itself; form input/change events are counted when available.
- **Not verified:** Docker is unavailable in this environment, so the Keycloak container and actual OIDC sign-in have not been exercised. No managed IdP credentials are configured.
- **Not deployed:** `render.yaml` provisions the web service and Postgres, but the app has not been deployed to a public URL. Render account/deployment and Upstash Redis values are external prerequisites.

## Latest Verification

- **47 passed, 1 skipped** in the full PyTest suite; Ruff lint/format and editor diagnostics pass.
- Keycloak realm JSON, Render blueprint, and Docker Compose YAML parse successfully.
- Live simulator check: headless scenario scores 85/100 with five explanations; simulated requests do not change persisted event totals.
- Batch API tests verify 3–25 bounds, per-request outcomes, separate simulation totals/history, and unchanged real block totals.
- Live autofill-like signals score 43 (`review`/allow); multiple strong automation signals score 78 and block.
- The integrated browser confirmed sign-in, batch simulation, and the dashboard. Standalone Playwright E2E was attempted but could not launch because Chromium is unavailable; browser download is blocked by the environment's TLS certificate chain.
- Docker is not installed in this environment, so Keycloak startup and real OIDC/M2M exchanges remain unverified.

## Remaining Work

1. **Verify IdP:** Start local Keycloak where Docker is available, validate realm import and the OIDC login-to-welcome flow, then validate a service-account JWT against `/api/private`.
2. **Deploy the public demo:** Create the Render service from the blueprint; provide a strong `SESSION_SECRET` and TLS Upstash `REDIS_URL`; register the deployed callback with a production OIDC provider if enabling sign-in. Confirm the public simulator works when OIDC is intentionally left unconfigured.
3. **Production validation:** Test persistence across app restarts against hosted Postgres, verify chart totals/history and Redis rate limiting, review database migrations/backup retention, and then publish the public URL.

## Verification

- PyTest and Ruff are required after each backend change.
- Playwright browser tests cover simulation selection, evaluate/explanation, sign-in demo, welcome/logout, and dashboard navigation when Chromium is available.
- Do not describe risk scores as certain human/bot identification; they are explainable heuristics.
- Do not treat the local Keycloak credentials as production secrets.
