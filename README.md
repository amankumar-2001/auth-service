# auth-service

A production-shaped authentication microservice implementing the login/auth PRD:
signup, signin, OTP/MFA verification, JWT + rotating refresh tokens, password
reset, social-login scaffolding, RBAC, audit logging, and rate limiting.

Built in Go with a layered architecture (Gin router, GORM/Postgres, go-redis,
Viper config, ozzo-validation) mirroring the reference service layout.

## Layout

```
cmd/                              entry point (graceful shutdown)
config/                           Viper config loader + structs
assets/kharchibook/                env JSON configs (ACTIVE_ENV selects one)
ddl/postgresql/                   versioned SQL schema (+ append-only audit trigger)
pkg/
  application/httpserver/         Gin router + v1 handlers
  domain/
    service/                      business logic (IXxxService + impl + tests)
    models/dao/                   GORM entities
    dto/{request,response,entity,message}
  infrastructure/
    sqlrepo/                      Postgres repositories (interface-based)
    cacherepo/                    Redis OTP / reset-token / rate-limit stores
    msgqueuerepo/                 Kafka notification publisher (logging stub)
    kms/                          AES-256-GCM PII encryption (local; KMS-swappable)
    transport/http/               Google OAuth client (scaffolded)
  di/                             dependency wiring (AppInterface + InitializeApp)
middleware/                       request-info, recovery, CORS, JWT/role/verified guards
third_party/platlogger/           structured logging wrapper
```

## Run locally

```bash
make infra-up          # Postgres + Redis via docker compose
make run               # ACTIVE_ENV=dev; auto-migrates + seeds RBAC roles
```

In `dev`, no signing key is configured so an **ephemeral RSA key** is generated
at startup (tokens don't survive a restart), and the generated OTP / reset token
is logged at WARN so you can complete flows without an SMS/email provider. Both
behaviours are dev-only.

Without Docker you can still run the test suite, which exercises the full flow
with in-memory fakes:

```bash
make test
```

## Key endpoints (`/v1/auth`)

| Method & path                       | Purpose                                  |
|-------------------------------------|------------------------------------------|
| `POST /signup`                      | Create account, trigger OTP              |
| `POST /login`                       | Verify credentials → access + refresh    |
| `POST /otp/verify`                  | Verify OTP, mark account verified        |
| `POST /otp/resend`                  | Re-send OTP (cooldown enforced)          |
| `POST /token/refresh`               | Rotate refresh token, issue new access   |
| `POST /logout`                      | Revoke session (optionally all)          |
| `POST /password/forgot`             | Issue reset token (non-enumerable)       |
| `POST /password/reset`              | Reset password, revoke all sessions      |
| `GET  /oauth/google[/callback]`     | Social-login flow (scaffolded)           |
| `GET  /me`                          | Current user (JWT-guarded)               |
| `GET  /.well-known/public-key`      | JWT verification public key (PEM)         |
| `GET  /healthz`, `/readyz`          | Liveness / readiness                     |

### Example

```bash
curl -s localhost:8080/v1/auth/signup -d '{"email":"a@b.com","password":"S3cure!pass","phone":"+919876543210"}'
# → {"userId":"1","verified":false,"message":"OTP sent"}   (OTP printed in server logs in dev)

curl -s localhost:8080/v1/auth/otp/verify -d '{"email":"a@b.com","otp":"123456"}'
curl -s localhost:8080/v1/auth/login      -d '{"email":"a@b.com","password":"S3cure!pass"}'
```

## Security properties (per PRD)

- Passwords hashed with **bcrypt** (per-hash salt embedded); never stored or logged in plaintext.
- OTPs, refresh tokens, and reset tokens stored only as **SHA-256 hashes** (OTP/reset in Redis with TTL).
- Short-lived **RS256 JWT** + long-lived **rotating** refresh token; rotated-token replay is detected and revokes the session family.
- Password reset **revokes all sessions**.
- Phone PII encrypted with **AES-256-GCM** (swap `kms.NewLocalKMS` for a cloud-KMS impl in prod).
- Rate limiting on login (per-IP) and password reset (per-email); per-account lockout after repeated failures.
- Immutable **audit log** (DB trigger blocks UPDATE/DELETE) for all security-relevant events.
- Gateway/services verify tokens locally via the published public key — no per-request call back to auth-service.

## Production notes

- Set `store.autoMigrate=false` and apply `ddl/postgresql/*.sql` via your migration tool.
- Provide a persistent RSA key via `token.privateKeyPath` / `token.publicKeyPath`.
- Replace the stub Kafka publisher and local KMS with real implementations behind their existing interfaces.
- Wire the live Google token-exchange + JWKS verification in `transport/http/google-oauth.go`.
