# n8n-nodes-patchmon

n8n community nodes for [PatchMon](https://github.com/PatchMon/PatchMon), a self-hosted Linux
patch monitoring server. The node reads hosts, packages, host groups, repositories and patch
policies, starts, approves and cancels patch runs, and patches pending security updates across
hosts. The trigger starts workflows on new security updates, finished or failed patch runs and
offline hosts.

Requires n8n 2.45.0 or later. Verified against the PatchMon server source of v2.1.8 (tested) and
of `main` after v2.1.8: the routes, handlers and middleware used here are unchanged.

This project is not affiliated with or endorsed by PatchMon or its authors.

## Installation

From npm: Settings → Community Nodes → Install → `n8n-nodes-patchmon`.

### Manual installation (Docker)

1. Copy the package file into the container (here named `n8n`):

```bash
docker cp n8n-nodes-patchmon-0.1.0.tgz n8n:/tmp/
```

2. Install it in `~/.n8n/nodes`:

```bash
docker exec -it n8n sh -c "mkdir -p ~/.n8n/nodes && cd ~/.n8n/nodes && npm install --legacy-peer-deps /tmp/n8n-nodes-patchmon-0.1.0.tgz"
```

3. Restart n8n:

```bash
docker restart n8n
```

## Credentials

The PatchMon API credential has two parts.

| Field | Description |
|---|---|
| Base URL | Address of PatchMon without `/api/v1`, for example `https://patchmon.example.com`. http or https only, without user, query or fragment. Trailing slashes are removed. |
| Token Key, Token Secret | An Integration API token. Sent as Basic Auth only to `/api/v1/api/*`. |
| Username, Password | Optional service user. Needed only for host groups, repositories, patch policies and patching. |

### Integration API token

In PatchMon: Settings → Integrations → New Token, type **API**, scope `host` with only the action
`get`. Optionally restrict it to the IP address of n8n and set an expiry date. Copy the key and the
secret: PatchMon shows the secret once. The node never uses `host: delete`.

### Service user

PatchMon exposes patching, policies, host groups and repositories only through the API of its
web UI, which needs a signed-in user. Create a dedicated local user for n8n:

- a role with only `can_view_hosts` and `can_manage_patching`;
- a long random password and **no MFA**: n8n cannot answer a two-factor prompt;
- local sign-in enabled (an SSO-only user cannot be used).

n8n signs in with `POST /api/v1/auth/login` only when it has no access token or PatchMon refuses
it (401), at most once per execution, and stores the token encrypted in the credential. The token
is sent as `Authorization: Bearer` only to the Base URL and user it was issued for. Every sign-in
uses the same `X-Device-ID`, so PatchMon reuses one session for n8n. Access tokens last one hour
by default (`JWT_EXPIRES_IN`); after that the next request signs in again.

### Credential test

The test calls `GET /api/v1/api/hosts` with the token. With a service user, it first signs in and
checks that the role has `can_view_hosts` and `can_manage_patching`. It reports a wrong token
(401), a missing scope or IP restriction (403), a wrong password, MFA, missing permissions,
local sign-in turned off and the sign-in lockout (429).

## Node: PatchMon

| Resource | Operation | Endpoint | Access | Permission |
|---|---|---|---|---|
| Host | Get Many (filters: groups, status, OS, update and reporting state, reboot) | `GET /api/v1/api/hosts?include=stats` | Integration API | `host: get` |
| Host | Get, Get Stats, Get System, Get Network | `GET /api/v1/api/hosts/{id}/info`, `/stats`, `/system`, `/network` | Integration API | `host: get` |
| Host | Get Packages (only with updates, only security updates, name) | `GET /api/v1/api/hosts/{id}/packages` | Integration API | `host: get` |
| Host Group | Get Many, Get, Get Hosts | `GET /api/v1/host-groups[/{id}[/hosts]]` | Service user | `can_view_hosts` |
| Repository | Get Many (host, search, status, type), Get, Get by Host | `GET /api/v1/repositories…` | Service user | `can_view_hosts` |
| Patch Policy | Get Many, Get | `GET /api/v1/patching/policies[/{id}]` | Service user | `can_view_hosts` |
| Patching | Get Runs, Get Active Runs, Get Run, Preview Run | `GET /api/v1/patching/runs…`, `/preview-run` | Service user | `can_view_hosts` |
| Patching | Trigger Patch | `POST /api/v1/patching/trigger` | Service user | `can_manage_patching` |
| Patching | Approve Run | `POST /api/v1/patching/runs/{id}/approve` | Service user | `can_manage_patching` |
| Patching | Cancel Run | `POST /api/v1/patching/runs/{id}/stop` | Service user | `can_manage_patching` |
| Patching | Patch Security Updates | the reads above, then `POST /api/v1/patching/trigger` | Both | `host: get`, `can_view_hosts`, `can_manage_patching` |
| Custom API Call | Method, path, query, JSON body | `/api/v1/api/*` or other `/api/v1/*` | Chosen | Depends on the route |

The service user operations use PatchMon's internal web UI API. It is not a public API and can
change between PatchMon versions.

Trigger Patch, Approve Run and Patch Security Updates install updates on hosts; Cancel Run stops a
run. Their descriptions tell an AI agent to use them only on explicit request. Everything else
only reads data.

Lists support Return All / Limit and Split Into Items (on by default). Errors carry PatchMon's
message. With Continue On Fail the failing item returns `{ error }`.

### Trigger Patch

Selected Packages (`patch_package`, up to 100 names) or All Packages (`patch_all`). `dry_run` and
`pending_approval` are always sent explicitly; `schedule_override: immediate` only with Run
Immediately. Without it the run follows the host's patch policy (immediately, after a delay or at
a fixed time).

- **Skip If Run Active** (default on): if the host already has a scheduled, queued, running or
  waiting run, nothing is started and the item has `status: skipped`. PatchMon itself refuses
  only a second queued or running run (409).
- **Wait For Completion**: polls the run until it ends (Max Wait up to 60 minutes, interval at
  least 5 s). A run that its policy schedules after Max Wait (for example a fixed night window) is
  returned at once with `waited: false`. Follow it with the trigger instead.
- PatchMon refuses selected packages on Arch Linux (pacman): use All Packages there.

### Patch Security Updates

For all hosts, some host IDs or some host groups, with Exclude Hosts and Exclude Groups (IDs or
names). For every host with security updates it starts one `patch_package` run with only the
packages PatchMon flags as `is_security_update`, `dry_run: false` and `pending_approval: false`,
following the patch policy unless Run Immediately is on.

All reads happen first. If the sign-in fails or the Integration API answers unexpectedly, the node
fails before starting anything. Then the runs are started; an error on one host is reported for
that host and the others go on. Hosts are skipped (with a reason) when they have no security
updates, have an active or scheduled run, run Arch Linux, or are excluded. Dry Run starts nothing
and returns what would be started. Max Hosts (default 100) refuses larger selections.

Output: one item per host (default)

```json
{ "host_id": "…", "host_name": "web-01", "status": "started", "packages": ["libssl3", "openssl"],
  "package_count": 2, "patch_run_id": "…", "run_at": "2026-11-20T02:00:00Z", "dry_run": false }
```

or one summary item with `hosts_started`, `packages_started`, `started`, `skipped` (with reason)
and `errors`.

## Trigger: PatchMon Trigger

Polling trigger. The first run records the current state and fires nothing. In test mode it
returns a real example from current data. Filters: host IDs and host groups.

| Event | Fires when | Access |
|---|---|---|
| New Security Updates | A host has a security update (package and version) it did not have at the previous poll | Integration API |
| Patch Run Finished | A run ends `completed` | Service user |
| Patch Run Failed | A run ends `failed`, `timed_out` or `agent_disconnected` (dry runs optional) | Service user |
| Host Offline | No contact from the agent for N minutes (`last_update`); fires once until the host reports again | Integration API |

Example item for Patch Run Failed:

```json
{ "event": "patchRunFailed", "run_id": "…", "host_id": "…", "host_name": "db-01", "status": "timed_out",
  "patch_type": "patch_package", "package_names": ["openssh-server"], "error_message": "…",
  "completed_at": "2026-11-20T02:14:00Z" }
```

State is deduplicated and bounded (10,000 entries). After a sign-in failure the trigger stops
signing in, so polls do not keep PatchMon's lockout active; the error is reported once:

- 401: until the credential changes (save the corrected credential);
- 429: as long as PatchMon asks.

## Security

- The Integration API token goes only to `/api/v1/api/*`, the service user's token only to the
  other `/api/v1` routes of the Base URL. Neither ever appears in a URL.
- The password is sent only in the body of the sign-in request. Token, secret and password are
  removed from outputs, errors and messages, also with Continue On Fail.
- No redirect is followed. Requests time out after 60 s without data (30 s for sign-in);
  responses over 64 MiB are aborted.
- IDs used in paths are validated. Custom API Call refuses absolute URLs, path traversal (also
  percent-encoded), paths outside the chosen access type and sign-in, session and two-factor
  routes.
- Limits, waits, poll settings and host counts are checked also when set by expressions.
- No runtime dependencies.

## Support

If this node saves you time, you can [buy me a coffee](https://buymeacoffee.com/FDalCol).

## License

[MIT](LICENSE) © FDalCol
