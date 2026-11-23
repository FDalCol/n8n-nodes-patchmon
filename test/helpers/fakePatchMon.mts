/**
 * Minimal fake PatchMon 2.1.8 server. Like the real one it checks two separate kinds of
 * authentication: Basic Auth with an API token on /api/v1/api/* (ApiAuth + RequireApiScope) and
 * a Bearer access token on the other /api/v1 routes (AuthWithSessionCheck + RequirePermission).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export const TOKEN_KEY = 'patchmon_ae_0123456789abcdef';
export const TOKEN_SECRET = 'Integr4tion-Secret-Value-0123';
export const USERNAME = 'n8n-service';
export const PASSWORD = 'Serv1ce-Passw0rd!';

export const HOST_A = '11111111-1111-4111-8111-111111111111';
export const HOST_B = '22222222-2222-4222-8222-222222222222';
export const HOST_ARCH = '33333333-3333-4333-8333-333333333333';
export const HOST_CLEAN = '44444444-4444-4444-8444-444444444444';
export const GROUP_PROD = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const GROUP_LAB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
export const POLICY_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

export const PERMISSIONS = ['can_view_hosts', 'can_manage_patching'];

export interface RecordedRequest {
	method: string;
	path: string;
	query: URLSearchParams;
	headers: Record<string, string | string[] | undefined>;
	body: string;
	json: unknown;
}

export interface Reply {
	status?: number;
	json?: unknown;
	raw?: string;
	headers?: Record<string, string>;
	delayMs?: number;
}

export type Handler = (req: RecordedRequest, params: Record<string, string>) => Reply | Promise<Reply>;

export interface Pkg {
	id: string;
	name: string;
	current_version: string;
	available_version: string | null;
	needs_update: boolean;
	is_security_update: boolean;
}

export interface Host {
	id: string;
	friendly_name: string;
	hostname: string;
	ip: string;
	os_type: string;
	os_version: string;
	status: string;
	last_update: string;
	package_manager: string;
	needs_reboot: boolean;
	groups: string[];
	packages: Pkg[];
	/** Minutes the patch policy of the host delays a run (0 = immediate). */
	policyDelayMinutes: number;
}

export interface Run {
	id: string;
	host_id: string;
	job_id: string;
	patch_type: string;
	package_name: string | null;
	package_names: string[];
	status: string;
	dry_run: boolean;
	shell_output: string;
	error_message: string | null;
	scheduled_at: string;
	started_at: string;
	completed_at: string;
	created_at: string;
	updated_at: string;
	/** Statuses the run goes through when it advances. */
	plan: string[];
}

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString().replace(/\.\d{3}Z$/, 'Z');

function pkg(name: string, security: boolean, update = true): Pkg {
	return {
		id: `pkg-${name}`,
		name,
		current_version: '1.0.0',
		available_version: update ? '1.0.1' : null,
		needs_update: update,
		is_security_update: security && update,
	};
}

function defaultHosts(): Host[] {
	return [
		{
			id: HOST_A,
			friendly_name: 'web-01',
			hostname: 'web-01.example.lan',
			ip: '192.0.2.11',
			os_type: 'Ubuntu',
			os_version: '24.04',
			status: 'active',
			last_update: minutesAgo(5),
			package_manager: 'apt',
			needs_reboot: false,
			groups: [GROUP_PROD],
			packages: [pkg('openssl', true), pkg('libssl3', true), pkg('vim', false), pkg('bash', false, false)],
			policyDelayMinutes: 0,
		},
		{
			id: HOST_B,
			friendly_name: 'db-01',
			hostname: 'db-01.example.lan',
			ip: '192.0.2.12',
			os_type: 'Debian',
			os_version: '12',
			status: 'active',
			last_update: minutesAgo(10),
			package_manager: 'apt',
			needs_reboot: true,
			groups: [GROUP_PROD],
			packages: [pkg('openssh-server', true), pkg('curl', false)],
			policyDelayMinutes: 0,
		},
		{
			id: HOST_ARCH,
			friendly_name: 'arch-lab',
			hostname: 'arch-lab.example.lan',
			ip: '192.0.2.13',
			os_type: 'Arch Linux',
			os_version: 'rolling',
			status: 'active',
			last_update: minutesAgo(15),
			package_manager: 'pacman',
			needs_reboot: false,
			groups: [GROUP_LAB],
			packages: [pkg('glibc', true)],
			policyDelayMinutes: 0,
		},
		{
			id: HOST_CLEAN,
			friendly_name: 'clean-01',
			hostname: 'clean-01.example.lan',
			ip: '192.0.2.14',
			os_type: 'Rocky Linux',
			os_version: '9',
			status: 'active',
			last_update: minutesAgo(20),
			package_manager: 'dnf',
			needs_reboot: false,
			groups: [GROUP_LAB],
			packages: [pkg('kernel', false, false)],
			policyDelayMinutes: 0,
		},
	];
}

const GROUPS: Record<string, string> = { [GROUP_PROD]: 'Production', [GROUP_LAB]: 'Lab' };

let runCounter = 0;
let tokenCounter = 0;

function newRunId(): string {
	runCounter++;
	return `dddddddd-dddd-4ddd-8ddd-${String(runCounter).padStart(12, '0')}`;
}

/** An access token in the JWT shape PatchMon returns. */
function newAccessToken(): string {
	tokenCounter++;
	return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLW44biIsIm4iOj${tokenCounter}fQ.SignatureValue${String(tokenCounter).padStart(6, '0')}abcdefXYZ`;
}

interface Route {
	method: string;
	regex: RegExp;
	names: string[];
	handler: Handler;
}

const BLOCKING_IN_DB = ['queued', 'pending_validation', 'running'];
const ACTIVE_LIST = ['scheduled', 'queued', 'running', 'pending_validation', 'pending_approval', 'validated'];

export class FakePatchMon {
	readonly requests: RecordedRequest[] = [];

	hosts: Host[] = defaultHosts();

	runs: Run[] = [];

	readonly sessions = new Set<string>();

	readonly issuedTokens: string[] = [];

	permissions = new Set(PERMISSIONS);

	scopes: string[] = ['get'];

	userTfa = false;

	tfaEnrolmentRequired = false;

	passwordChangeRequired = false;

	localAuthDisabled = false;

	lockedOut = false;

	/** Runs advance one status on every GET of the run. */
	autoAdvance = true;

	/** Basic Auth seen on a session route, or a Bearer token on an Integration API route. */
	readonly crossedCredentials: string[] = [];

	private routes: Route[] = [];

	private server = http.createServer((req, res) => {
		const chunks: Buffer[] = [];
		req.on('data', (c: Buffer) => chunks.push(c));
		req.on('end', () => {
			void this.handle(req, res, Buffer.concat(chunks));
		});
	});

	constructor() {
		this.installDefaults();
	}

	async start(): Promise<this> {
		await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
		return this;
	}

	async stop(): Promise<void> {
		this.server.closeAllConnections();
		await new Promise<void>((resolve) => this.server.close(() => resolve()));
	}

	get url(): string {
		return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
	}

	reset(): void {
		this.requests.length = 0;
		this.hosts = defaultHosts();
		this.runs = [];
		this.sessions.clear();
		this.issuedTokens.length = 0;
		this.permissions = new Set(PERMISSIONS);
		this.scopes = ['get'];
		this.userTfa = false;
		this.tfaEnrolmentRequired = false;
		this.passwordChangeRequired = false;
		this.localAuthDisabled = false;
		this.lockedOut = false;
		this.autoAdvance = true;
		this.crossedCredentials.length = 0;
		this.routes = [];
		this.installDefaults();
	}

	on(method: string, pattern: string, handler: Handler): this {
		const names: string[] = [];
		const regex = new RegExp(
			`^${pattern.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\\?\{([^}]+)\\?\}/g, (_m, n: string) => {
				names.push(n);
				return '([^/]+)';
			})}$`,
		);
		this.routes.unshift({ method, regex, names, handler });
		return this;
	}

	requestsTo(method: string, path: string): RecordedRequest[] {
		return this.requests.filter((r) => r.method === method && r.path === path);
	}

	get logins(): RecordedRequest[] {
		return this.requestsTo('POST', '/api/v1/auth/login');
	}

	get triggers(): RecordedRequest[] {
		return this.requestsTo('POST', '/api/v1/patching/trigger');
	}

	host(id: string): Host {
		const h = this.hosts.find((x) => x.id === id);
		if (!h) throw new Error(`no host ${id}`);
		return h;
	}

	addRun(hostId: string, status: string, extra: Partial<Run> = {}): Run {
		const id = newRunId();
		const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
		const run: Run = {
			id,
			host_id: hostId,
			job_id: `patch-run-${id}`,
			patch_type: 'patch_package',
			package_name: null,
			package_names: ['openssl'],
			status,
			dry_run: false,
			shell_output: 'Reading package lists...',
			error_message: null,
			scheduled_at: '',
			started_at: '',
			completed_at: ['completed', 'failed', 'timed_out', 'agent_disconnected', 'cancelled'].includes(status) ? now : '',
			created_at: now,
			updated_at: now,
			plan: [],
			...extra,
		};
		this.runs.push(run);
		return run;
	}

	/** One step of a run: scheduled/queued -> running -> plan or completed; pending_validation -> validated. */
	advance(run: Run): void {
		const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
		if (run.status === 'queued') {
			Object.assign(run, { status: 'running', started_at: now });
		} else if (run.status === 'running') {
			Object.assign(run, { status: run.plan.shift() ?? 'completed', completed_at: now, shell_output: `${run.shell_output}\nDone.` });
		} else if (run.status === 'pending_validation') {
			Object.assign(run, { status: 'validated', completed_at: now });
		}
	}

	revokeSessions(): void {
		this.sessions.clear();
	}

	private hostJson(h: Host, stats: boolean): Record<string, unknown> {
		const out: Record<string, unknown> = {
			id: h.id,
			friendly_name: h.friendly_name,
			hostname: h.hostname,
			ip: h.ip,
			host_groups: h.groups.map((g) => ({ id: g, name: GROUPS[g] })),
		};
		if (stats) {
			const outdated = h.packages.filter((p) => p.needs_update).length;
			const security = h.packages.filter((p) => p.is_security_update).length;
			Object.assign(out, {
				os_type: h.os_type,
				os_version: h.os_version,
				last_update: h.last_update,
				status: h.status,
				effective_status: h.status === 'active' && Date.parse(h.last_update) < Date.now() - 120 * 60_000 ? 'inactive' : h.status,
				needs_reboot: h.needs_reboot,
				updates_count: outdated,
				security_updates_count: security,
				total_packages: h.packages.length,
				reporting_state: Date.parse(h.last_update) >= Date.now() - 60 * 60_000 ? 'reporting' : 'stale',
				update_state: security > 0 ? 'security_required' : outdated > 0 ? 'updates_pending' : 'up_to_date',
			});
		}
		return out;
	}

	private runJson(run: Run): Record<string, unknown> {
		const h = this.hosts.find((x) => x.id === run.host_id);
		const { plan: _plan, ...rest } = run;
		return {
			...rest,
			triggered_by_username: USERNAME,
			hosts: { id: run.host_id, friendly_name: h?.friendly_name ?? null, hostname: h?.hostname ?? null, os_type: h?.os_type ?? null },
		};
	}

	private perm(name: string): Reply | null {
		return this.permissions.has(name) ? null : { status: 403, json: { error: 'Insufficient permissions' } };
	}

	private installDefaults(): void {
		this.on('GET', '/api/v1/api/hosts', (req) => {
			const stats = (req.query.get('include') ?? '').split(',').includes('stats');
			const filter = (req.query.get('hostgroup') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
			let hosts = this.hosts;
			if (filter.length) {
				const ids = filter.map((f) => (GROUPS[f] ? f : Object.keys(GROUPS).find((k) => GROUPS[k] === f))).filter(Boolean);
				if (!ids.length) return { json: { hosts: [], total: 0, filtered_by_groups: filter } };
				hosts = hosts.filter((h) => h.groups.some((g) => ids.includes(g)));
			}
			return { json: { hosts: hosts.map((h) => this.hostJson(h, stats)), total: hosts.length } };
		});
		const hostOr404 = (id: string) => this.hosts.find((h) => h.id === id);
		this.on('GET', '/api/v1/api/hosts/{id}/info', (_r, p) => {
			const h = hostOr404(p.id);
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			return { json: { ...this.hostJson(h, false), os_type: h.os_type, os_version: h.os_version, agent_version: '2.1.8', machine_id: 'm-1' } };
		});
		this.on('GET', '/api/v1/api/hosts/{id}/stats', (_r, p) => {
			const h = hostOr404(p.id);
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			return {
				json: {
					host_id: h.id,
					total_installed_packages: h.packages.length,
					outdated_packages: h.packages.filter((x) => x.needs_update).length,
					security_updates: h.packages.filter((x) => x.is_security_update).length,
					total_repos: 3,
				},
			};
		});
		this.on('GET', '/api/v1/api/hosts/{id}/system', (_r, p) =>
			hostOr404(p.id) ? { json: { id: p.id, architecture: 'x86_64', kernel_version: '6.8.0', needs_reboot: false } } : { status: 404, json: { error: 'Host not found' } },
		);
		this.on('GET', '/api/v1/api/hosts/{id}/network', (_r, p) =>
			hostOr404(p.id) ? { json: { id: p.id, ip: '192.0.2.11', gateway_ip: '192.0.2.1', dns_servers: ['192.0.2.53'], network_interfaces: [] } } : { status: 404, json: { error: 'Host not found' } },
		);
		this.on('GET', '/api/v1/api/hosts/{id}/packages', (req, p) => {
			const h = hostOr404(p.id);
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			const updatesOnly = req.query.get('updates_only') === 'true';
			const packages = h.packages
				.filter((x) => !updatesOnly || x.needs_update)
				.map((x) => ({ ...x, description: '', category: 'net', last_checked: h.last_update }));
			return { json: { host: { id: h.id, hostname: h.hostname, friendly_name: h.friendly_name }, packages, total: packages.length } };
		});

		this.on('POST', '/api/v1/auth/login', (req) => {
			if (this.localAuthDisabled) return { status: 403, json: { error: 'Local authentication is disabled. Please use SSO.' } };
			if (this.lockedOut) {
				return { status: 429, headers: { 'Retry-After': '120' }, json: { message: 'Too many failed login attempts. Try again later.', remaining_seconds: 120 } };
			}
			const body = (req.json ?? {}) as Record<string, unknown>;
			if (body.username !== USERNAME || body.password !== PASSWORD) return { status: 401, json: { error: 'Invalid credentials' } };
			if (this.userTfa) {
				return { json: { message: 'TFA verification required', requiresTfa: true, username: USERNAME, tfaTicket: 'ticket-should-not-leak' } };
			}
			const token = newAccessToken();
			this.sessions.add(token);
			this.issuedTokens.push(token);
			const answer: Record<string, unknown> = {
				message: 'Login successful',
				token,
				refresh_token: `refresh-${token}`,
				expires_in: 3600,
				expires_at: new Date(Date.now() + 3600_000).toISOString(),
				user: { id: 'user-n8n', username: USERNAME, email: 'n8n@example.invalid', role: 'patcher' },
			};
			if (this.tfaEnrolmentRequired) answer.tfaEnrolmentRequired = true;
			if (this.passwordChangeRequired) answer.passwordChangeRequired = true;
			return { json: answer, headers: { 'Set-Cookie': `token=${token}; HttpOnly; Path=/` } };
		});
		this.on('GET', '/api/v1/auth/profile', () => ({ json: { user: { id: 'user-n8n', username: USERNAME } } }));
		this.on('GET', '/api/v1/permissions/user-permissions', () => {
			if (!this.permissions.size) return { status: 403, json: { error: 'No permissions found' } };
			const all = ['can_view_dashboard', 'can_view_hosts', 'can_manage_hosts', 'can_view_packages', 'can_manage_patching'];
			return { json: Object.fromEntries(all.map((p) => [p, this.permissions.has(p)])) };
		});

		this.on('GET', '/api/v1/hosts/{id}', (_r, p) => {
			const denied = this.perm('can_view_hosts');
			if (denied) return denied;
			const h = hostOr404(p.id);
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			return { json: { ...this.hostJson(h, true), package_manager: h.package_manager, api_id: 'patchmon_host_api_id' } };
		});
		this.on('GET', '/api/v1/host-groups', () =>
			this.perm('can_view_hosts') ?? {
				json: Object.entries(GROUPS).map(([id, name]) => ({ id, name, description: null, color: '#3B82F6', _count: { hosts: this.hosts.filter((h) => h.groups.includes(id)).length } })),
			},
		);
		this.on('GET', '/api/v1/host-groups/{id}', (_r, p) =>
			GROUPS[p.id] ? { json: { id: p.id, name: GROUPS[p.id] } } : { status: 404, json: { error: 'Host group not found' } },
		);
		this.on('GET', '/api/v1/host-groups/{id}/hosts', (_r, p) =>
			GROUPS[p.id] ? { json: this.hosts.filter((h) => h.groups.includes(p.id)).map((h) => ({ id: h.id, friendly_name: h.friendly_name })) } : { status: 404, json: { error: 'Host group not found' } },
		);
		const repos = Array.from({ length: 7 }, (_, i) => ({ id: `repo-${i + 1}`, name: `repo ${i + 1}`, url: `https://mirror.example/${i + 1}`, is_active: i !== 6, is_secure: i % 2 === 0, host_count: 1 }));
		this.on('GET', '/api/v1/repositories', (req) => {
			const limit = Number(req.query.get('limit') ?? 50);
			const offset = Number(req.query.get('offset') ?? 0);
			let rows = repos;
			if (req.query.get('status') === 'active') rows = rows.filter((r) => r.is_active);
			if (req.query.get('type') === 'secure') rows = rows.filter((r) => r.is_secure);
			if (!req.query.has('limit')) return { json: rows };
			return { json: { items: rows.slice(offset, offset + Math.min(limit, 3)), total: rows.length, limit, offset } };
		});
		this.on('GET', '/api/v1/repositories/{id}', (_r, p) => {
			const r = repos.find((x) => x.id === p.id);
			return r ? { json: { ...r, host_repositories: [] } } : { status: 404, json: { error: 'Repository not found' } };
		});
		this.on('GET', '/api/v1/repositories/host/{id}', (_r, p) => ({ json: hostOr404(p.id) ? repos.slice(0, 2) : [] }));

		this.on('GET', '/api/v1/patching/policies', () => ({
			json: [{ id: POLICY_ID, name: 'Weekend window', patch_delay_type: 'fixed_time', fixed_time_utc: '02:00', _count: { assignments: 1, exclusions: 0 } }],
		}));
		this.on('GET', '/api/v1/patching/policies/{id}', (_r, p) =>
			p.id === POLICY_ID
				? { json: { id: POLICY_ID, name: 'Weekend window', patch_delay_type: 'fixed_time', fixed_time_utc: '02:00', assignments: [], exclusions: [] } }
				: { status: 404, json: { error: 'Policy not found' } },
		);
		this.on('GET', '/api/v1/patching/preview-run', (req) => {
			const h = hostOr404(req.query.get('host_id') ?? '');
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			return { json: { host_id: h.id, host_name: h.friendly_name, run_at_iso: new Date(Date.now() + h.policyDelayMinutes * 60_000).toISOString(), policy_name: 'Default (immediate)', patch_delay_type: 'immediate' } };
		});
		this.on('GET', '/api/v1/patching/runs', (req) => {
			const denied = this.perm('can_view_hosts');
			if (denied) return denied;
			const limit = Math.max(1, Math.min(200, Number(req.query.get('limit') ?? 50)));
			const offset = Math.max(0, Number(req.query.get('offset') ?? 0));
			const status = req.query.get('status') ?? '';
			const hostId = req.query.get('host_id') ?? '';
			let rows = this.runs.filter((r) => !hostId || r.host_id === hostId);
			if (status === 'active') rows = rows.filter((r) => BLOCKING_IN_DB.includes(r.status));
			else if (status) rows = rows.filter((r) => r.status === status);
			const pt = req.query.get('patch_type');
			if (pt) rows = rows.filter((r) => r.patch_type === pt);
			if (req.query.get('sort_by') === 'completed_at') rows = [...rows].sort((a, b) => b.completed_at.localeCompare(a.completed_at));
			return {
				json: { runs: rows.slice(offset, offset + limit).map((r) => this.runJson(r)), pagination: { total: rows.length, limit, offset, pages: Math.ceil(rows.length / limit) } },
			};
		});
		this.on('GET', '/api/v1/patching/runs/{id}', (_r, p) => {
			const denied = this.perm('can_view_hosts');
			if (denied) return denied;
			const run = this.runs.find((r) => r.id === p.id);
			if (!run) return { status: 404, json: { error: 'Patch run not found' } };
			if (this.autoAdvance) this.advance(run);
			return { json: { ...this.runJson(run), items: [], package_ids: {} } };
		});
		// Registered after /runs/{id}: the last registered route wins
		this.on('GET', '/api/v1/patching/runs/active', () => this.perm('can_view_hosts') ?? ({
			json: { runs: this.runs.filter((r) => ACTIVE_LIST.includes(r.status)).map((r) => this.runJson(r)) },
		}));
		this.on('POST', '/api/v1/patching/runs/{id}/stop', (_r, p) => {
			const denied = this.perm('can_manage_patching');
			if (denied) return denied;
			const run = this.runs.find((r) => r.id === p.id);
			if (!run) return { status: 404, json: { error: 'Patch run not found' } };
			if (['completed', 'failed', 'cancelled', 'timed_out', 'agent_disconnected', 'validated'].includes(run.status)) {
				return { status: 409, json: { error: 'Run already finished' } };
			}
			run.status = 'cancelled';
			return { json: { ok: true, cancelled_via: 'db_only' } };
		});
		this.on('POST', '/api/v1/patching/runs/{id}/approve', (req, p) => {
			const denied = this.perm('can_manage_patching');
			if (denied) return denied;
			const run = this.runs.find((r) => r.id === p.id);
			if (!run) return { status: 404, json: { error: 'Patch run not found' } };
			if (!['validated', 'pending_validation', 'pending_approval'].includes(run.status)) {
				return { status: 400, json: { error: 'Only validated, pending-validation, or pending-approval runs can be approved' } };
			}
			run.status = 'approved';
			const immediate = (req.json as { schedule_override?: string } | undefined)?.schedule_override === 'immediate';
			const delay = immediate ? 0 : this.host(run.host_id).policyDelayMinutes;
			const created = this.addRun(run.host_id, delay ? 'scheduled' : 'queued', { package_names: run.package_names });
			return { json: { message: 'Approved - new patch run created', patch_run_id: created.id, validation_run_id: run.id, run_at: new Date(Date.now() + delay * 60_000).toISOString() } };
		});
		this.on('POST', '/api/v1/patching/trigger', (req) => {
			const denied = this.perm('can_manage_patching');
			if (denied) return denied;
			const body = (req.json ?? {}) as Record<string, unknown>;
			const h = hostOr404(String(body.host_id ?? ''));
			if (!h) return { status: 404, json: { error: 'Host not found' } };
			if (body.patch_type !== 'patch_all' && body.patch_type !== 'patch_package') {
				return { status: 400, json: { error: 'patch_type must be patch_all or patch_package' } };
			}
			if (body.dry_run && body.pending_approval) return { status: 400, json: { error: 'dry_run and pending_approval are mutually exclusive' } };
			if (body.patch_type === 'patch_package' && h.package_manager === 'pacman') {
				return { status: 400, json: { error: 'Arch Linux does not support partial upgrades, so PatchMon cannot patch selected packages on this host. Use Patch all.' } };
			}
			if (body.dry_run && body.patch_type !== 'patch_package') return { status: 400, json: { error: 'dry_run is only supported for patch_package' } };
			const names = Array.isArray(body.package_names) ? (body.package_names as string[]) : [];
			if (body.patch_type === 'patch_package' && (!names.length || names.length > 100)) {
				return { status: 400, json: { error: 'Valid package_name or non-empty package_names is required for patch_package' } };
			}
			const immediate = body.schedule_override === 'immediate';
			const delay = body.dry_run || body.pending_approval || immediate ? 0 : h.policyDelayMinutes;
			const status = body.pending_approval ? 'pending_approval' : body.dry_run ? 'pending_validation' : delay ? 'scheduled' : 'queued';
			if (BLOCKING_IN_DB.includes(status) && this.runs.some((r) => r.host_id === h.id && BLOCKING_IN_DB.includes(r.status))) {
				return { status: 409, json: { error: 'A patch run is already queued or in progress on this host. Wait for it to finish, or cancel it, before starting another.' } };
			}
			const run = this.addRun(h.id, status, { patch_type: String(body.patch_type), package_names: names, dry_run: body.dry_run === true });
			const runAt = new Date(Date.now() + delay * 60_000).toISOString();
			if (body.pending_approval) {
				return { json: { message: 'Submitted for approval', patch_run_id: run.id, job_id: run.job_id, run_at: runAt, queued: false, pending_approval: true } };
			}
			return {
				json: { message: body.dry_run ? 'Dry run queued' : delay ? `Patch scheduled for ${runAt}` : 'Patch queued', patch_run_id: run.id, job_id: run.job_id, run_at: runAt, queued: true },
			};
		});
	}

	private authorize(req: RecordedRequest): Reply | null {
		const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
		const integration = req.path === '/api/v1/api' || req.path.startsWith('/api/v1/api/');
		if (integration) {
			if (auth.startsWith('Bearer ')) this.crossedCredentials.push(`Bearer on ${req.path}`);
			if (!auth.startsWith('Basic ')) return { status: 401, json: { error: 'Missing or invalid authorization header' } };
			const [key, secret] = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8').split(':');
			if (key !== TOKEN_KEY) return { status: 401, json: { error: 'Invalid API key' } };
			if (secret !== TOKEN_SECRET) return { status: 401, json: { error: 'Invalid API secret' } };
			if (!this.scopes.includes('get')) return { status: 403, json: { error: 'Access denied', message: 'This API key does not have permission to get host' } };
			return null;
		}
		if (auth.startsWith('Basic ')) this.crossedCredentials.push(`Basic on ${req.path}`);
		if (req.path === '/api/v1/auth/login') return null;
		if (!auth.startsWith('Bearer ')) return { status: 401, raw: '{"error":"Unauthorized"}\n' };
		if (!this.sessions.has(auth.slice(7))) return { status: 401, raw: '{"error":"Session expired"}\n' };
		if (this.tfaEnrolmentRequired && req.path !== '/api/v1/auth/profile') {
			return { status: 403, json: { error: 'Two-factor authentication setup is required', code: 'TFA_ENROLMENT_REQUIRED' } };
		}
		return null;
	}

	private async handle(req: http.IncomingMessage, res: http.ServerResponse, raw: Buffer) {
		const url = new URL(req.url ?? '/', 'http://localhost');
		const body = raw.toString('utf8');
		let json: unknown;
		try {
			json = body ? JSON.parse(body) : undefined;
		} catch {
			json = undefined;
		}
		const recorded: RecordedRequest = { method: String(req.method), path: url.pathname, query: url.searchParams, headers: req.headers, body, json };
		this.requests.push(recorded);

		const send = (reply: Reply) => {
			const status = reply.status ?? 200;
			const payload = reply.raw !== undefined ? reply.raw : JSON.stringify(reply.json ?? null);
			res.writeHead(status, { 'Content-Type': 'application/json', ...(reply.headers ?? {}) });
			res.end(payload);
		};

		const denied = this.authorize(recorded);
		if (denied) return send(denied);
		for (const route of this.routes) {
			if (route.method !== recorded.method) continue;
			const m = route.regex.exec(url.pathname);
			if (!m) continue;
			const params: Record<string, string> = {};
			route.names.forEach((n, i) => (params[n] = decodeURIComponent(m[i + 1])));
			const reply = await route.handler(recorded, params);
			if (reply.delayMs) await new Promise((r) => setTimeout(r, reply.delayMs));
			return send(reply);
		}
		return send({ status: 404, raw: '404 page not found\n', headers: { 'Content-Type': 'text/plain' } });
	}
}

/** A second server that must never receive anything (redirect target). */
export class Trap {
	readonly hits: Array<{ url: string; headers: Record<string, unknown> }> = [];

	private server = http.createServer((req, res) => {
		this.hits.push({ url: String(req.url), headers: req.headers });
		res.writeHead(200, { 'Content-Type': 'application/json' });
		res.end('{"stolen":true}');
	});

	async start(): Promise<this> {
		await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
		return this;
	}

	get url(): string {
		return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
	}

	async stop(): Promise<void> {
		this.server.closeAllConnections();
		await new Promise<void>((resolve) => this.server.close(() => resolve()));
	}
}
