# Single-Node Service-Level Objectives

These are the launch objectives for the supported single-node deployment. The
service owner approves changes; the on-call owner enforces the error-budget
policy. Multi-node availability is outside the current architecture.

## Objectives

| User journey | SLI and window | Objective |
|---|---|---|
| HTTP tunnel availability | Eligible 2xx+3xx responses divided by eligible 2xx+3xx+5xx responses, rolling 30 days | >= 99.90% |
| HTTP tunnel overhead | One-minute synthetic probe: tunneled p95 minus direct-upstream p95, rolling 30 days | <= 5 ms for >= 99.0% of probes |
| Control connection | Synthetic authenticated control connects, rolling 30 days | >= 99.90% successful |
| Tunnel setup | Synthetic authenticated HTTP tunnel creation, rolling 30 days | >= 99.90% successful and p95 <= 100 ms |
| Reconnect recovery | Canary session restored after a forced network break | >= 99.0% within 10 s; p95 <= 5 s over 30 days |
| ACME renewal | Completed renewal attempts, rolling 90 days | >= 99.0% successful; no loaded certificate below 7 days remaining |

HTTP 4xx responses are excluded from the availability ratio because they are
caller policy/input outcomes. Every 5xx response counts, including offline
tunnels and upstream failures visible to the visitor. Planned maintenance is
not excluded. Synthetic and load traffic must carry a scraper-side marker and
is excluded from customer-request volume, while its dedicated journey SLI is
retained. Low-traffic windows rely on synthetic probes rather than treating no
requests as success.

## Signals

- Request availability and server duration use
  `wirerift_http_requests_total{class=...}` and
  `wirerift_http_request_duration_seconds_*` from `/metrics`.
- Certificate risk uses `wirerift_certificate_expiry_timestamp_seconds`; any
  increase in `wirerift_persistence_errors_total` is a page, not budgeted loss.
- Control connect, setup, overhead, and reconnect are black-box canary journeys
  executed from outside the node. Store both success and duration series.
- ACME attempts use structured renewal logs plus the certificate-expiry gauge.
  Absence of the scheduled canary or scraper is monitoring failure and pages.

## Error budget and alerts

A 99.90% 30-day objective permits 0.10% bad eligible events; for a continuously
probed availability journey this is 43 minutes 12 seconds. Request-based budget
is `eligible_events * 0.001`. Do not combine unrelated journey budgets.

Page when both windows exceed the same burn threshold:

- fast burn: 14.4x over 5 minutes and 1 hour;
- slow burn: 6x over 30 minutes and 6 hours;
- certificate expiry below 14 days, persistence errors, missing telemetry, or
  readiness loss for five minutes page independently of the budget.

Freeze non-remediation releases when a journey has exhausted its 30-day budget
or consumed more than 50% in seven days. Resume after the service owner records
the cause, remediation, and remaining risk. Emergency security releases retain
rollback authority but still require a canary.

## Release evidence

Before production launch, staging must demonstrate all synthetic journeys,
dashboard queries, paging routes, and the two burn-rate alerts. A benchmark run
is capacity evidence only; it cannot satisfy these SLOs. Retain the dashboard
snapshot, alert test, benchmark records, and restore/rollback drill with the
approved image digest.
