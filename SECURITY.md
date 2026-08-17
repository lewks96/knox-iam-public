# Security

## There is no supported version

Knox is a hobby project. It is not maintained on a schedule, has never had a security
review, and is not deployed or operated anywhere. Please do not run it in front of real
users or real data — see the warning at the top of the [README](README.md).

| Version | Supported |
|---------|-----------|
| all | ❌ |

## Reporting

If you find a vulnerability, opening a GitHub issue is fine — there is nothing here worth
coordinating disclosure over, because there is no deployment to protect and no user to
warn. A reproduction and a pointer at the offending code is more useful than a severity
rating.

Expect a slow response, or none.

## Things already known to be weak

- No security review, internal or external, has ever been done.
- Throttling covers the password login path only — per tenant, per IP, and per account,
  as Redis counters, plus an MFA attempt lockout. The `/oauth2/token` grant path has
  nothing in front of it but the ingress `limit-rps` annotation, and the Redis counters
  are best-effort: they are not a defence against a distributed attacker.
- `AES_MASTER_KEY` is a single static key in an environment variable. There is no KMS
  integration, no envelope encryption, and no key rotation path for tenant signing keys.
- Secrets in `k8s/` are plain Kubernetes Secrets seeded by shell scripts.
- The audit log is written off the request path through a bounded channel. When that
  channel is full the database insert is dropped rather than blocking the request, so the
  queryable audit table is best-effort. (The event still reaches the OTLP pipeline as a
  `knox::audit` log record.)
- Test coverage is unit- and service-level; there is no fuzzing, no property testing of
  the token paths, and no adversarial test suite.
