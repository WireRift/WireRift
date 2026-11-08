# WireRift Production Operations Runbook

This runbook is the operational source of truth for a single-node WireRift
deployment. It covers the controls that must be completed outside the codebase:
release verification, DNS and firewall setup, secret handling, deployment,
monitoring, backup and restore, incident recovery, and rollback. `README.md`
remains the command reference; `SPECIFICATION.md` and `IMPLEMENTATION.md` are
historical design documents.

## Required ownership

Assign a named primary and backup for each role before public traffic is enabled.

| Role | Responsibility |
|---|---|
| Service owner | Release approval, SLOs, canary decision, rollback authority |
| On-call operator | Alerts, incident coordination, token revocation, traffic isolation |
| DNS owner | A, AAAA, wildcard, and custom-domain TXT records |
| Security owner | Secret store, firewall policy, artifact verification, access review |
| Backup owner | Encrypted snapshots, retention, restore drills, recovery evidence |

## Production prerequisites

- Use an immutable release image digest, never `latest`, for production.
- Keep dashboard port 4040 on loopback or behind an authenticated TLS reverse
  proxy. Do not expose its plain HTTP listener directly.
- Allow inbound 80/TCP, 443/TCP, 4443/TCP, and only the configured TCP tunnel
  range. Deny every other inbound port by default.
- Point the base domain and wildcard DNS record at the node. Port 80 must reach
  WireRift for ACME HTTP-01.
- When an L7 proxy is required, configure only its exact networks with
  `--trusted-proxy-cidrs`. The proxy must overwrite/sanitize `X-Forwarded-For`,
  and direct access to the WireRift edge must be blocked at the network layer.
  Without this flag WireRift discards visitor-supplied forwarding identity and
  uses the socket peer; malformed or oversized trusted-proxy chains also fail
  closed to that peer.
- Store the bootstrap token in a mounted read-only secret file. Do not place it
  in CLI arguments, Compose YAML, shell history, or an image layer.
- Place `/data/certs` on persistent encrypted storage with restricted access.

## Verify a release

Verify downloaded binaries before installation:

```bash
sha256sum --ignore-missing -c checksums.txt
gh attestation verify wirerift-linux-amd64 --repo WireRift/WireRift
```

For containers, record and deploy the registry digest printed by the release
workflow:

```bash
docker pull ghcr.io/wirerift/wirerift@sha256:<approved-digest>
docker image inspect ghcr.io/wirerift/wirerift@sha256:<approved-digest> \
  --format '{{json .RepoDigests}}'
```

The release workflow attaches an SBOM, max-level build provenance, and signed
GitHub provenance to the published image. CI rejects high or critical findings
detected in the runtime OS or Go binaries.

## Prepare secrets and configuration

Generate the Compose bootstrap token without putting the value in an argument:

```bash
umask 077
openssl rand -hex 32 > /secure/path/wirerift-token
export WIRERIFT_TOKEN_FILE=/secure/path/wirerift-token
export WIRERIFT_DOMAIN=tunnel.example.com
export WIRERIFT_ACME_EMAIL=ops@example.com
docker compose config --quiet
```

Use `wirerift-server token create` for individual users and automation. The
bootstrap token is an emergency administrative credential; keep its use rare
and rotate the mounted file through the platform secret workflow.

The persistent certificate volume contains all of the following and must be
backed up as one consistency unit:

- `acme-account.key`: durable ACME account identity;
- `*.crt` and `*.key`: issued certificates and private keys;
- `domain-secret`: custom-domain ownership proof key;
- `tokens.json`: hashed managed tokens and account policy;
- `held.json`: temporarily reserved subdomains and TCP ports (`tcp:<port>`).

## First staging deployment

Use a separate staging domain and Let's Encrypt staging before production.

1. Confirm A, AAAA, and wildcard answers from at least two public resolvers.
2. Confirm firewall exposure matches the prerequisite allowlist.
3. Start the exact release candidate digest with `-acme-staging`.
4. Connect a client through `tls://<domain>:4443`.
5. Exercise HTTP, WebSocket, TCP, reconnect, and graceful shutdown paths.
6. Confirm an ACME renewal or forced staging re-issuance completes.
7. Run a 24 to 72 hour soak and review resource growth, reconnects, and errors.
8. Repeat without `-acme-staging` only after the staging evidence is accepted.

## Deploy and canary

```bash
docker compose pull
docker compose up -d
curl -fsS http://127.0.0.1/health/ready
curl -fsS http://127.0.0.1/metrics   # loopback needs no token; remote callers send a Bearer token
```

Deploy one canary node first. Keep the previous image digest and volume snapshot
available until the canary window ends. Promote only after tunnel creation,
reconnect, certificate, latency, and error signals remain within the service
owner's approved SLOs.

## Health and alerting

- `/healthz` is liveness. A failure means the HTTP process is unreachable.
- `/health/ready` is readiness. It returns 503 before all configured listeners
  and maintenance loops start, as soon as graceful drain begins, and immediately
  after an unexpected control/HTTP/HTTPS listener failure. A required listener
  or dashboard serving failure also makes the process exit non-zero so the
  supervisor can restart the whole instance; WireRift never attempts a partial
  in-process restart.
- `/metrics` exports readiness, uptime, active sessions/tunnels, edge bytes,
  bounded HTTP status classes, a fixed global latency histogram, the earliest
  in-memory certificate expiry, and persistent-state write errors. HTTP metrics
  intentionally have no path, host, method, account, or tunnel labels.
- `/metrics` answers loopback callers without credentials (a request that carries
  `X-Forwarded-For`/`Forwarded` is not treated as loopback) and every other
  caller only with `Authorization: Bearer <token>`. Point a remote Prometheus at
  it with `authorization.credentials_file`.
- The dashboard's **Connect** tab (every account) builds the install and `wirerift` commands for this server from `GET /api/connect`: the control address (`tls://` when the control plane serves TLS), public URL scheme, TCP port range and reserved subdomains. Set `-domain` to the public name so the commands carry it.
- Administrators create and revoke tokens in the **Admin** tab (`/api/admin/tokens`): it edits the same `tokens.json` as `wirerift-server token ...` and applies the change at once; a server without a token file answers 501. Back up `tokens.json` as before.
- Accounts can also sign in to the dashboard with a username (the account name) and a password: set it with `wirerift-server token passwd -account NAME` (password from `WIRERIFT_PASSWORD` or stdin) or in the Admin tab. Hashes are PBKDF2-HMAC-SHA256 in `tokens.json`; sessions last 12 hours, live in memory and end on restart, password change or deactivation.
- The dashboard has an **Admin** tab for administrator tokens (`token create -admin`): health, one hour of
  rate/latency/memory/fd history, accounts, sessions (with Disconnect), held subdomains, certificate expiry
  and the Activity log. Reach it with `ssh -L 4040:127.0.0.1:4040 host` or publish it with
  `-dashboard-host dashboard` (HTTPS only, token required, rate limited). The history and the activity log
  are in memory only and start empty after a restart; use `/metrics` and the journal for anything longer.
- `-edge-rate` and `-edge-burst` set the per-visitor-IP request limit of the HTTP
  edge (defaults 100 req/s, burst 50). Raise them when a busy site or a proxy
  without `-trusted-proxy-cidrs` makes many visitors share one IP.
- When a token file is in use and no bootstrap token (`-token`, `WIRERIFT_TOKEN`,
  `WIRERIFT_TOKEN_FILE`) is given, the random first-run token is disabled instead
  of being printed to the log.

Alert when `wirerift_persistence_errors_total` increases or when
`wirerift_certificate_expiry_timestamp_seconds - time()` enters the approved
renewal window. An expiry value of zero means no certificate has been loaded
into the TLS cache yet. Build request/error-rate and latency SLOs from the
fixed status-class counters and histogram buckets; do not add visitor-derived
labels at the scraper.

At minimum alert on readiness failure, restart loops, disk usage, certificate
expiry, repeated ACME failures, authentication floods, control connection
failure, tunnel setup failure, and unexpected session/tunnel drops. Define
targets for control-connect success, tunnel setup p95, edge latency overhead,
reconnect time, and ACME renewal success before launch.

## Fault and endurance evidence

`go run ./test/fault/` uses an unprivileged TCP proxy to add bidirectional
latency, hard connection drops, a connection-refusing partition, and a
heartbeat-ack blackhole. Every scenario requires the same reconnect-enabled
client and original tunnel identity to recover within five seconds. It runs on
every change and in the scheduled soak workflow.

`go run ./test/soak/ -duration 30m -window 1m` records per-window p95/p99,
rejected and transport errors, successful throughput, goroutine growth, and
live-heap growth. `.github/workflows/soak.yml` runs it daily for 30 minutes; use
`workflow_dispatch` with `duration=2h` before launch and after transport,
multiplexer, proxy, or resource-limit changes. Retain the workflow URL and
summary with release evidence.

The user-space proxy is deterministic TCP failure coverage, not kernel packet
loss/reordering. Real staging must additionally run `tc netem` (or the cloud
network's equivalent) for packet loss, jitter, reordering, and MTU/fragmentation
under the same black-box SLO probes.

## Backup and restore

The recovery objectives for the single-node deployment are:

- RPO: 24 hours. Create at least one verified backup every day and immediately
  before a release, storage migration, certificate-volume change, or intentional
  ACME account replacement.
- RTO: 30 minutes from declaring recovery to an isolated readiness pass.
- Retention: keep 7 daily, 4 weekly, and 12 monthly verified backups. Apply the
  stricter legal or business retention rule when one exists.
- Drill cadence: restore to a clean volume monthly, before public launch, and
  after changing the storage layout, backup format, or encryption-key process.

`wirerift-backup` is included in the server image. It encrypts the compressed
archive as it is written with chunked AES-256-GCM, so no plaintext archive is
stored. Its authenticated JSON inventory contains the mode, size, and SHA-256 manifest
digest for every regular file. Restore rejects a wrong key, corruption,
truncation, trailing data, unsafe paths, links, special files, duplicate paths,
manifest mismatches, and non-empty targets. A new target is published only after
the whole archive passes authentication; an existing target is accepted only
when it is an empty fresh volume. Restore also rejects archives over 100,000
entries, individual files over 1 GiB, or more than 4 GiB of total file data; use
an infrastructure snapshot workflow if a future state layout legitimately
exceeds these bounds.

The state directory currently contains the ACME account key, managed
certificate/key/metadata files, `domain-secret`, `tokens.json`, and `held.json`.
Back up the complete directory so future state files are included. The bootstrap
token secret is mounted separately and must never be placed in the state
directory or backup.

### Key setup

Create a separate 256-bit key in the production secret store. Materialize it
only for the backup job, outside the WireRift state volume, owned by the job UID,
with mode `0600`. Never store it beside, inside, or under the same access policy
as the `.wrb` backup.

```bash
umask 077
openssl rand -hex 32 > /secure/wirerift-backup.key
chmod 600 /secure/wirerift-backup.key
```

The tool accepts 32 raw bytes or 64 hexadecimal characters. Loss of this key
makes its backups unrecoverable. During rotation, create and verify a new backup
with the new key before retiring the old key; retain old keys until every backup
encrypted by them expires.

### Create and verify

Stop WireRift first. An atomic storage snapshot is also acceptable, but run the
tool against that read-only snapshot rather than the changing live directory.
The output path must be off the state volume and must not already exist.

```bash
systemctl stop wirerift

wirerift-backup create \
  --source /var/lib/wirerift/certs \
  --output /var/backups/wirerift/wirerift-$(date -u +%Y%m%dT%H%M%SZ).wrb \
  --key /secure/wirerift-backup.key

wirerift-backup verify \
  --input /var/backups/wirerift/<backup>.wrb \
  --key /secure/wirerift-backup.key

systemctl start wirerift
```

For Compose, use the exact approved image digest already set in
`WIRERIFT_IMAGE`. `BACKUP_DIR` must be an absolute, access-controlled host path;
the backup key remains a separate read-only mount.

```bash
export BACKUP_DIR=/var/backups/wirerift
export BACKUP_KEY=/secure/wirerift-backup.key
export BACKUP_FILE="wirerift-$(date -u +%Y%m%dT%H%M%SZ).wrb"

docker compose stop wirerift-server
docker compose run --rm --no-deps \
  --entrypoint wirerift-backup \
  -v "$BACKUP_DIR:/backup" \
  -v "$BACKUP_KEY:/run/secrets/wirerift_backup_key:ro" \
  wirerift-server create \
  --source /data/certs --output "/backup/$BACKUP_FILE" \
  --key /run/secrets/wirerift_backup_key

docker compose run --rm --no-deps \
  --entrypoint wirerift-backup \
  -v "$BACKUP_DIR:/backup:ro" \
  -v "$BACKUP_KEY:/run/secrets/wirerift_backup_key:ro" \
  wirerift-server verify \
  --input "/backup/$BACKUP_FILE" \
  --key /run/secrets/wirerift_backup_key
docker compose start wirerift-server
```

Upload only a successfully verified `.wrb` file to immutable off-node storage.
Record its backup ID, object version, image digest, key version, UTC time,
operator/job identity, and verification result. Alert if the last successful
verified backup exceeds 24 hours or if retention cannot be enforced.

### Restore drill and incident restore

Restore only to a new path or a fresh empty volume. Do not restore over a live or
previously used state directory.

```bash
wirerift-backup verify \
  --input /var/backups/wirerift/<backup>.wrb \
  --key /secure/wirerift-backup.key

wirerift-backup restore \
  --input /var/backups/wirerift/<backup>.wrb \
  --target /var/lib/wirerift-restore/certs \
  --key /secure/wirerift-backup.key
```

For a container restore, create a new volume and mount it at the image's
pre-owned `/data/certs` path. Never attach the production volume to the drill.

```bash
export RESTORE_VOLUME=wirerift-certs-restore-$(date -u +%Y%m%dT%H%M%SZ)
docker volume create "$RESTORE_VOLUME"
docker run --rm --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges \
  --entrypoint wirerift-backup \
  -v "$RESTORE_VOLUME:/data/certs" \
  -v "$BACKUP_DIR:/backup:ro" \
  -v "$BACKUP_KEY:/run/secrets/wirerift_backup_key:ro" \
  "$WIRERIFT_IMAGE" restore \
  --input "/backup/$BACKUP_FILE" --target /data/certs \
  --key /run/secrets/wirerift_backup_key
```

Then complete the recovery acceptance test:

1. Provision an isolated staging node with the same approved WireRift image
   digest and point it at only the newly restored state path/volume.
2. Mount the bootstrap token through the secret store, not from the backup.
3. Confirm restored ownership is the runtime UID and modes remain restrictive.
4. Start on isolated addresses and require `/health/ready` to pass.
5. Verify managed tokens, custom-domain TXT proofs, cached certificates, and
   held subdomains and TCP ports behave as before; exercise control, HTTP, WebSocket, and TCP.
6. Record the duration, operator, backup ID, object/key versions, image digest,
   test results, and discrepancies. Destroy the drill volume after evidence is
   retained.

A backup that has not passed both `verify` and a clean-volume drill is not a
recovery mechanism. The repository tests validate the format and restore logic;
they do not prove access to the production secret store, off-node object, or
infrastructure during an incident.

## Incident procedures

### Revoke a token

```bash
wirerift-server token list
wirerift-server token revoke <token-id>
```

The running server reloads the token file within five seconds; `SIGHUP` requests
an immediate reload. Confirm the affected sessions and tunnels close.

### ACME outage

Do not delete `acme-account.key`. On restart, WireRift enters degraded mode only
when the existing account key and a currently valid base-domain certificate are
both intact. It serves the cached certificate and retries ACME initialization
every five minutes. If either artifact is missing, invalid, expired, or for a
different hostname, startup fails closed.

For a corrupt account key, stop the service and restore the complete volume from
the last verified backup. Intentional ACME account replacement requires a
security-owner-approved recovery plan and a new backup; it is not an automatic
repair action.

### Certificate expiry or renewal failure

Check public port 80 routing, DNS answers, system time, disk space, and ACME
logs. Keep serving a still-valid cached certificate. Do not replace production
TLS with self-signed mode. Roll back only if the prior digest and the current
volume are compatible.

### Disk pressure or write failure

Stop creating tunnels, preserve logs, and free space outside the certificate
volume. Never remove account keys, certificate keys, `domain-secret`, or token
state as cleanup. After recovery, verify atomic certificate writes and take a
fresh encrypted snapshot.

### Port exhaustion or bind failure

Confirm the configured TCP range, firewall rules, and listener ownership. A
startup bind failure is fatal and rolls back listeners; do not bypass it by
starting a partial plaintext service.

A TCP port that a dropped client held stays reserved for its account for
`-offline-grace` (shown as `tcp:<port>` under held in the Admin tab), so
"port already taken" for a fixed `RemotePort` right after a disconnect is expected
for every account but the owner. Clients older than 1.18 do not ask for their
old port again and get a new one; raise `-offline-grace` for longer protection.

## Rollback

1. Stop new deployment activity and capture logs and current metrics.
2. Select the recorded previous immutable image digest.
3. Determine whether the incident changed persistent state. Restore a snapshot
   only when required; never roll certificate state backward casually.
4. Deploy the prior digest, verify readiness, then test control, HTTP, WebSocket,
   and TCP paths.
5. Keep the failed digest quarantined and open a post-incident review.

## Routine maintenance

- Weekly: review Dependabot action/base-image updates and CI vulnerability gate.
- Monthly: review token/account access, firewall rules, disk trend, and alerts.
- Monthly: perform a clean-node restore drill and token-revocation exercise.
- Before every stable release: verify provenance, record image digest and SBOM,
  run staging soak, confirm rollback digest, and obtain service-owner approval.
