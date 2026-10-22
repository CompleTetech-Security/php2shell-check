# WordPress free-scan integration

This integration connects a saved, signed CompleteTech free-scan request to a
single passive PHP2Shell check. It consists of the MU plugin in
`integrations/wordpress/`, the Python controller and restricted network adapter
in `integrations/worker/`, and the deployment files in `deployment/`.

The standalone checker retains its existing behavior. Do not expose its CLI
directly to form inputs. The integration checks the website's public homepage
and robots policy; it does not implement the broader manual security review.

```mermaid
flowchart LR
  A[Signed form saved] --> B[Acceptance and exact scope persisted]
  B --> C[Confirmation email]
  C --> D[Explicit confirmation POST]
  D --> E[Durable queue]
  E --> F[Authenticated worker claim and start]
  F --> G[Restricted passive checker]
  G --> H[Private result and manual review]
  H --> I[Reviewed report to original contact]
```

## Safety and delivery semantics

- The queue is populated only by the explicit `ct_promo_request_ready` action.
  Editing a post or sending a notification does not start a scan. Old requests
  are not imported. The target, original contact and accepted terms are copied
  into the job rather than read from later edits to request text.
- Confirmation tokens are hashed at rest, short lived, and consumed by an
  explicit POST. GET requests, including email-security prefetches, cannot
  confirm. Mailbox control is not independent proof of domain ownership.
- Jobs have atomic claims. A claim that was never started can be recovered;
  a started job with an uncertain outcome is not automatically scanned again.
  A lost result acknowledgement retries the stored receipt, not the scan.
- The adapter pins each connection to a validated public IP while retaining the
  original hostname for TLS verification and SNI. All DNS answers must pass;
  every page and robots request is checked. Proxies are disabled. Another host,
  including a `www` variant, requires new authorization.
- The worker only receives one normalized homepage, an opaque lease, and scope
  identifiers. It receives no customer email, WordPress password, database
  password or SMTP secret. The scanner subprocess drops privileges and does
  not receive the worker authentication key.
- `potentially_affected`, `fixed_version_reported`, and `unknown` retain their
  original meanings. Exploitability is always `not_tested`. Unknown, blocked,
  timed-out or malformed results never become a safety verdict.
- Completing the automated portion does not complete the promised full review.
  The other checks remain manual work. Report transport acceptance and confirmed
  delivery are distinct, as are report delivery and scanner completion.

## Worker protocol

The three POST routes are `claim`, `start` and `result`, under
`/wp-json/ct-scan/v1/`.
Each request carries `X-CT-Timestamp` (Unix seconds), `X-CT-Nonce` (32 lowercase
hex characters), and `X-CT-Signature` (HMAC-SHA256 hex). The signed string is the
timestamp, nonce, `POST`, route without `/wp-json`, and raw-body SHA-256 joined
with newlines. Timestamps have a five-minute tolerance; nonces are consumed
atomically. Bodies are bounded to 64 KiB and only exact permitted fields are
accepted. Protect the worker key as an execution credential.

`claim` accepts `{}` and returns `{"job":null}` or one job containing `id`,
`target`, `scope_hash`, `terms_hash`, `expires_at`, `lease` and `lease_until`.
Both expiry fields are integer Unix seconds. `start` accepts `id`, `lease`
and `scope_hash`. `result` accepts those plus `outcome`, `result`, `error` and
`checker_revision`. A completed result has `error:""`; a failed result has
`result:null` and a safe error category. Acknowledgements are `{"ok":true}`.
The scan output is bounded to 32 KiB. A replayed identical receipt is accepted
idempotently; changing its contents is a conflict.

Receipt retries stop at authorization expiry or one hour after lease expiry,
whichever comes first. Permanent rejection keeps the receipt in the private
quarantine for operator reconciliation; it never initiates a new scan.
Quarantine is bounded to 100 receipts and at most one year. Inspect its reason
and the WordPress job before taking any manual action. Do not copy these
records into public issues or logs.

Before upgrading the pinned revision or rotating the key, stop accepting new
work, drain/reconcile existing receipts and stop the controller. Do not change
the expected revision while old receipts are awaiting acknowledgement.

## Repository and site ownership

The maintained integration is published in this repository. The CompleteTech
site is a separate WordPress control/context checkout, with production files
managed over its documented SSH alias. Read that checkout's `AGENTS.md` and
`DOMAIN_CONTEXT.md`; do not assume a local website build/deploy pipeline.

`deployment/complete-tech-site.patch` contains only the required edits to the
existing handler, acceptance recorder, form messages and terms. It preserves
the existing referral and administrator-mail logic. Its manifest records the
inspected, newline-normalized before hashes and the prepared after hashes.
Those hashes are evidence for this patch, not permission to overwrite later
changes. If production has moved, review and rebase the patch.

To prepare the patch against the inspected local site files:

```sh
python deployment/prepare_site_patch.py --source /path/to/complete.tech
```

The command writes prepared files under `.work/site/` and a patch/manifest;
it does not change the site checkout or production. It requires exact anchors
and refuses an unexpected baseline. Inspect the diff before using it.

The new terms version is `2026-10-21-r2`. It explains the confirmation step and
the automated/manual split without narrowing existing agreements. Update the
terms page and `ct_promo_terms()` together. The recorder sets `_ct_terms_saved`
only after reading back the complete acceptance. The handler stores
`_ct_scan_target`, `_ct_scan_email`, `_ct_scan_name` and `_ct_ref`, checks those
values, then emits the action.

## Runner and scheduling

The deployment uses a dedicated Docker container with Python 3.12. The base
image is pinned by digest. The source revision is supplied as
`CT_SCAN_REVISION`; build from that exact reviewed checkout. This is separate
from the checker's embedded vulnerability-rule date.

The controller polls WordPress every 15 seconds and performs maintenance with
its claims, so it does not depend on visitor-triggered WP-Cron. Docker's
`unless-stopped` policy restarts the controller after a crash or Docker restart.
The queue lives in WordPress and pending receipts live in a private named
volume. On Docker Desktop the host and Docker must stay running; a sleeping or
offline workstation delays service. Move the same deployment to an always-on
Linux Docker host if that availability is required.

The container has no published ports, no Docker socket, no host source mount,
a read-only root filesystem, memory/CPU/process limits, and only the SETUID,
SETGID and KILL capabilities needed to drop scanner privileges and terminate a
timed-out child running under a different UID. The controller's key and
spool remain root-only; the scanner runs as UID/GID 65534. This is process
isolation with a shared kernel, not a separate virtual machine.

The chosen code and integration are published under this repository's license
terms. Preserve `LICENSE`, `LICENSING.md` and copyright notices. Review the
applicable source-availability or commercial licensing arrangements for a
different deployment; do not assume the older MIT release applies.

## Validation

The Python test suite uses synthetic results, mocked DNS/transports and local
fixtures. It must not contact external targets:

```sh
python -m unittest -v
python wordpress_check.py --help
git diff --check
```

For real WordPress/database integration checks, use the disposable environment:

```sh
docker compose -p php2shell-issue6-test -f deployment/compose.test.yaml up -d --wait
docker compose -p php2shell-issue6-test -f deployment/compose.test.yaml exec -T wordpress php /work/deployment/test-bootstrap.php
docker compose -p php2shell-issue6-test -f deployment/compose.test.yaml exec -T wordpress php /work/integrations/wordpress/tests/integration.php
```

The test network is internal. Test email is intercepted in the test process.
Only the explicitly named test project may be removed afterwards. The fixed
test subnet can be overridden with `CT_TEST_SUBNET` after checking for overlap.
Never use the bootstrap file with an existing WordPress installation.

After preparing the site patch locally, also exercise the actual modified
handler and acceptance recorder against this fixture:

```sh
docker compose -p php2shell-issue6-test -f deployment/compose.test.yaml exec -T wordpress php /work/deployment/test-site-patch.php
```

This optional check needs the prepared `.work/site/` files, intercepts email,
and covers saved requests, referral attribution, the attached contract,
confirmation gating, stale/missing terms, invalid nonce, honeypot, malformed
target and failed acceptance persistence. It uses the real promotion window;
after that offer expires, refresh its fixture deliberately instead of enabling
an expired offer in production.

## Configuration and operator setup

Production enablement is a separate operation from merging this integration.
The default configuration is disabled, and no historical request sweep exists.

1. Copy `integrations/wordpress/ct-scan.php` to the site's `wp-content/mu-plugins/`.
   Use `deployment/wordpress-config.example.php` for
   `wp-content/ct-scan-private/config.php`. Install `deployment/private.htaccess`
   as that directory's `.htaccess`, make the directory mode 0700, and make its
   configuration and key mode 0600 under the PHP process's account. Verify the
   server actually denies HTTP access; `.htaccess` is specific to compatible
   Apache configurations. Do not enable the plugin until this check passes.
2. Generate a cryptographically random 32-byte-or-longer key without logging it.
   Store its text representation in `ct-scan-private/worker.key` and in a dedicated
   external Docker volume named `ct-php2shell-secrets`, at `/key` (root-owned,
   mode 0600, parent mode 0700). These must contain the same bytes after trimming
   the trailing newline. On Docker Desktop use a Linux named volume so Windows
   bind-mount permissions cannot expose the key to the scanner child.
3. Set `expected_checker_revision` to the reviewed 40-character Git commit and
   keep `enabled` false. Build from a clean checkout of that commit using the
   same value for `CT_SCAN_REVISION`. Check `git status --porcelain` first; the
   revision string is provenance, not a substitute for a clean reviewed build.
4. Build with `docker compose -p ct-php2shell -f deployment/compose.yaml build`,
   then start with the same command prefix and `up -d`. The API origin is fixed
   to `https://complete.tech`; changing sites requires a reviewed code change.
   Check for subnet conflicts before using the default worker subnet.
5. Apply the reviewed site patch/terms update, then set `enabled` true. The
   runner must authenticate successfully before accepting live submissions.
   A matching revision and key are required; mismatches fail closed.

The healthcheck requires a successful authenticated exchange in the last ten
minutes. Use `docker compose -p ct-php2shell -f deployment/compose.yaml ps` and
bounded `logs --tail 50` for runner health, and the Promo Requests scan panel
for queue age, authorization and report state. A healthy container does not
mean that a particular customer's scan succeeded or that email was delivered.
Docker restart policy restarts a stopped process, not an unhealthy process;
investigate persistent unhealthy state instead of automatically resetting jobs.

## Rollout and rollback

1. Read the live site files and compare them with the inspected baseline. Keep
   backups in an HTTP-denied directory. Preserve unrelated site changes.
2. Install the MU plugin and its protected private configuration while disabled.
   Keep the authentication key out of source control and logs. Verify direct
   HTTP requests cannot retrieve any configuration or backup file.
3. Apply the reviewed handler/terms/form patch and update the published terms
   page in the same maintenance window. Preserve old request contracts.
4. Provision the controller's root-only key volume, build the reviewed revision,
   start the worker, then enable new submissions. Verify authenticated idle
   polling, replay rejection and a controlled fixture receipt. Do not backfill
   leads or scan prospects as a deployment test.
5. Check queue ages and failed/unknown outcomes in Promo Requests. Check runner
   health independently of customer-result status. Validate private result
   access and browser confirmation behavior before considering rollout complete.

To stop new work, disable the integration configuration and stop only this
Compose project. Preserve its receipt volume and WordPress queue for
reconciliation. Revoke/cancel affected authorization before any later restart.
Do not delete running-job records to make the queue look healthy. To restore
site files, restore the scoped backups; existing accepted contracts and queue
evidence must remain available. A started job with a missing receipt needs
operator investigation, not a blind retry.

Retention follows the accepted policy: scan results twelve months, and request
and acceptance records three years. Maintenance must preserve current work and
must not delete unrelated WordPress content. Authentication replay records and
bounded controller logs have shorter operational lifetimes.
