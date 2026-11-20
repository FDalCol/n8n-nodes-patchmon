import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FakePatchMon, GROUP_LAB, HOST_A, HOST_ARCH, HOST_B, HOST_CLEAN } from './helpers/fakePatchMon.mts';
import { credentials, runNodeError, runNodeJson } from './helpers/harness.mts';

let server: FakePatchMon;

beforeAll(async () => {
	server = await new FakePatchMon().start();
});
afterAll(async () => {
	await server.stop();
});
beforeEach(() => server.reset());

const trigger = (extra: Record<string, unknown> = {}) => ({
	resource: 'patching',
	operation: 'triggerPatch',
	hostId: HOST_A,
	patchType: 'patch_package',
	packageNames: 'openssl, libssl3',
	...extra,
});

describe('Trigger Patch', () => {
	it('dry run: sends dry_run and pending_approval explicitly, no schedule_override', async () => {
		const [out] = await runNodeJson({ credentials: credentials(server), params: trigger({ dryRun: true }) });
		expect(server.triggers[0].json).toEqual({
			host_id: HOST_A,
			patch_type: 'patch_package',
			dry_run: true,
			pending_approval: false,
			package_names: ['openssl', 'libssl3'],
		});
		expect(out).toMatchObject({ message: 'Dry run queued', queued: true, dry_run: true, host_id: HOST_A, schedule_override: null });
		expect(server.runs[0].status).toBe('pending_validation');
	});

	it('real run, with package names from an array and Run Immediately', async () => {
		const [out] = await runNodeJson({ credentials: credentials(server), params: trigger({ packageNames: ['openssl', 'openssl'], runImmediately: true }) });
		expect(server.triggers[0].json).toEqual({
			host_id: HOST_A,
			patch_type: 'patch_package',
			dry_run: false,
			pending_approval: false,
			package_names: ['openssl'],
			schedule_override: 'immediate',
		});
		expect(out).toMatchObject({ message: 'Patch queued', patch_run_id: server.runs[0].id, schedule_override: 'immediate' });
	});

	it('patch_all sends no package names; Pending Approval creates a waiting run', async () => {
		await runNodeJson({ credentials: credentials(server), params: trigger({ patchType: 'patch_all', pendingApproval: true }) });
		expect(server.triggers[0].json).toEqual({ host_id: HOST_A, patch_type: 'patch_all', dry_run: false, pending_approval: true });
		expect(server.runs[0].status).toBe('pending_approval');
	});

	it('validates input before sending anything', async () => {
		const cases: Array<[Record<string, unknown>, RegExp]> = [
			[{ dryRun: true, pendingApproval: true }, /cannot be used together/],
			[{ packageNames: 'openssl; rm -rf /' }, /is not a valid package name/],
			[{ packageNames: '' }, /Package Names is required/],
			[{ packageNames: Array.from({ length: 101 }, (_, i) => `p${i}`) }, /Too many entries \(maximum 100\)/],
			[{ hostId: 'web-01' }, /Host ID must be a UUID/],
			[{ waitForCompletion: true, maxWaitMinutes: 1000 }, /Max Wait \(Minutes\) must be an integer between 1 and 60/],
			[{ waitForCompletion: true, pollIntervalSeconds: 1 }, /Poll Interval \(Seconds\) must be an integer between 5 and 600/],
		];
		for (const [params, message] of cases) {
			expect((await runNodeError({ credentials: credentials(server), params: trigger(params) })).message).toMatch(message);
		}
		expect(server.triggers).toHaveLength(0);
	});

	it('Skip If Run Active: skips a host with a scheduled or waiting run without calling trigger', async () => {
		const scheduled = server.addRun(HOST_A, 'scheduled');
		const [out] = await runNodeJson({ credentials: credentials(server), params: trigger() });
		expect(out).toMatchObject({ host_id: HOST_A, status: 'skipped', reason: 'run_active', active_runs: [expect.objectContaining({ id: scheduled.id, status: 'scheduled' })] });
		expect(server.triggers).toHaveLength(0);
		// A finished dry run waiting for an optional approval does not block
		scheduled.status = 'cancelled';
		server.addRun(HOST_A, 'validated', { dry_run: true });
		const [started] = await runNodeJson({ credentials: credentials(server), params: trigger() });
		expect(started.patch_run_id).toBeTruthy();
	});

	it('without Skip If Run Active, PatchMon refuses a second active run (409)', async () => {
		server.addRun(HOST_A, 'running');
		const err = await runNodeError({ credentials: credentials(server), params: trigger({ skipIfRunActive: false }) });
		expect(err.message).toMatch(/^PatchMon API error 409: A patch run is already queued or in progress/);
		expect(server.requestsTo('GET', '/api/v1/patching/runs/active')).toHaveLength(0);
		// The same refusal, with Skip If Run Active on (a run created between check and trigger)
		server.on('GET', '/api/v1/patching/runs/active', () => ({ json: { runs: [] } }));
		const [out] = await runNodeJson({ credentials: credentials(server), params: trigger() });
		expect(out).toMatchObject({ status: 'skipped', reason: 'run_active' });
	});

	it('reports the refusal of selected packages on Arch Linux', async () => {
		const err = await runNodeError({ credentials: credentials(server), params: trigger({ hostId: HOST_ARCH, packageNames: 'glibc' }) });
		expect(err.message).toMatch(/Arch Linux does not support partial upgrades/);
		expect(err.description).toMatch(/All Packages/);
		const [all] = await runNodeJson({ credentials: credentials(server), params: trigger({ hostId: HOST_ARCH, patchType: 'patch_all' }) });
		expect(all.patch_run_id).toBeTruthy();
	});

	it('Wait For Completion polls the run until it ends', async () => {
		const [out] = await runNodeJson({
			credentials: credentials(server),
			params: trigger({ waitForCompletion: true, pollIntervalSeconds: 5, maxWaitMinutes: 1, includeOutput: false }),
		});
		expect(out).toMatchObject({ waited: true, finished: true, status: 'completed', run: { status: 'completed' } });
		expect((out.run as Record<string, unknown>).shell_output).toBeUndefined();
		// queued -> running at the first read; the second read 5 s later sees it finished
		expect(server.requestsTo('GET', `/api/v1/patching/runs/${String(out.patch_run_id)}`).length).toBeGreaterThanOrEqual(1);
	}, 20_000);

	it('Wait For Completion returns a terminal run at once and never waits for a run scheduled later', async () => {
		server.on('GET', '/api/v1/patching/runs/{id}', (_r, p) =>
			p.id === 'active' ? { json: { runs: [] } } : { json: { id: p.id, status: 'completed', shell_output: 'ok' } },
		);
		const [done] = await runNodeJson({ credentials: credentials(server), params: trigger({ waitForCompletion: true }) });
		expect(done).toMatchObject({ waited: true, finished: true, status: 'completed', run: { shell_output: 'ok' } });

		server.reset();
		server.host(HOST_A).policyDelayMinutes = 180;
		const [later] = await runNodeJson({ credentials: credentials(server), params: trigger({ waitForCompletion: true, maxWaitMinutes: 60 }) });
		expect(later).toMatchObject({ waited: false, message: expect.stringMatching(/^Patch scheduled for/) });
		expect(String(later.wait_note)).toMatch(/after Max Wait/);
		expect(server.requests.filter((r) => r.path.startsWith('/api/v1/patching/runs/dddd'))).toHaveLength(0);
	});

	it('Wait For Completion stops when the execution is cancelled', async () => {
		const controller = new AbortController();
		setTimeout(() => controller.abort(), 300);
		const err = await runNodeError({
			credentials: credentials(server),
			cancelSignal: controller.signal,
			params: trigger({ waitForCompletion: true, pollIntervalSeconds: 600, maxWaitMinutes: 60 }),
		}).catch((e: Error) => e);
		expect(err.message).toMatch(/cancelled/);
	}, 10_000);
});

describe('Approve Run and Cancel Run', () => {
	it('approves a run waiting for approval, with schedule_override only when asked', async () => {
		const waiting = server.addRun(HOST_A, 'pending_approval');
		const [out] = await runNodeJson({ credentials: credentials(server), params: { resource: 'patching', operation: 'approveRun', runId: waiting.id } });
		expect(out).toMatchObject({ message: 'Approved - new patch run created', validation_run_id: waiting.id });
		expect(server.requestsTo('POST', `/api/v1/patching/runs/${waiting.id}/approve`)[0].body).toBe('');
		const second = server.addRun(HOST_B, 'validated', { dry_run: true });
		await runNodeJson({ credentials: credentials(server), params: { resource: 'patching', operation: 'approveRun', runId: second.id, runImmediately: true } });
		expect(server.requestsTo('POST', `/api/v1/patching/runs/${second.id}/approve`)[0].json).toEqual({ schedule_override: 'immediate' });
		const err = await runNodeError({ credentials: credentials(server), params: { resource: 'patching', operation: 'approveRun', runId: waiting.id } });
		expect(err.message).toMatch(/400: Only validated/);
	});

	it('cancels a run and reports a finished one', async () => {
		const run = server.addRun(HOST_A, 'scheduled');
		const [out] = await runNodeJson({ credentials: credentials(server), params: { resource: 'patching', operation: 'cancelRun', runId: run.id } });
		expect(out).toEqual({ run_id: run.id, cancelled: true, cancelled_via: 'db_only' });
		const err = await runNodeError({ credentials: credentials(server), params: { resource: 'patching', operation: 'cancelRun', runId: run.id } });
		expect(err.message).toBe('PatchMon API error 409: Run already finished');
	});
});

const security = (extra: Record<string, unknown> = {}) => ({
	resource: 'patching',
	operation: 'patchSecurityUpdates',
	target: 'all',
	...extra,
});

describe('Patch Security Updates', () => {
	it('dry run: starts nothing and lists what would be started or skipped', async () => {
		const out = await runNodeJson({ credentials: credentials(server), params: security({ dryRun: true }) });
		expect(server.triggers).toHaveLength(0);
		const byHost = Object.fromEntries(out.map((r) => [r.host_id, r]));
		expect(byHost[HOST_A]).toMatchObject({ status: 'would_start', packages: ['libssl3', 'openssl'], package_count: 2, dry_run: true });
		expect(byHost[HOST_B]).toMatchObject({ status: 'would_start', packages: ['openssh-server'] });
		expect(byHost[HOST_ARCH]).toMatchObject({ status: 'skipped', reason: 'os_refused' });
		expect(byHost[HOST_CLEAN]).toMatchObject({ status: 'skipped', reason: 'no_security_updates' });
	});

	it('real: one patch_package run per host with only the security updates, following the policy', async () => {
		const out = await runNodeJson({ credentials: credentials(server), params: security() });
		expect(server.triggers.map((r) => r.json)).toEqual([
			{ host_id: HOST_A, patch_type: 'patch_package', package_names: ['libssl3', 'openssl'], dry_run: false, pending_approval: false },
			{ host_id: HOST_B, patch_type: 'patch_package', package_names: ['openssh-server'], dry_run: false, pending_approval: false },
		]);
		expect(out.filter((r) => r.status === 'started').map((r) => r.host_name)).toEqual(['web-01', 'db-01']);
		expect(out.find((r) => r.host_id === HOST_A)).toMatchObject({ patch_run_id: expect.any(String), run_at: expect.any(String) });
		// Every read happened before the first trigger
		const firstTrigger = server.requests.findIndex((r) => r.path === '/api/v1/patching/trigger');
		expect(server.requests.slice(firstTrigger).every((r) => r.path === '/api/v1/patching/trigger')).toBe(true);
	});

	it('Run Immediately sets schedule_override', async () => {
		await runNodeJson({ credentials: credentials(server), params: security({ target: 'hostIds', hostIds: HOST_A, runImmediately: true }) });
		expect(server.triggers[0].json).toMatchObject({ schedule_override: 'immediate' });
	});

	it('skips hosts with an active run and excluded hosts or groups', async () => {
		server.addRun(HOST_B, 'pending_approval');
		const out = await runNodeJson({ credentials: credentials(server), params: security({ securityOptions: { excludeGroups: 'Lab' } }) });
		const byHost = Object.fromEntries(out.map((r) => [r.host_id, r]));
		expect(byHost[HOST_B]).toMatchObject({ status: 'skipped', reason: 'run_active' });
		expect(byHost[HOST_ARCH]).toMatchObject({ status: 'skipped', reason: 'excluded' });
		expect(byHost[HOST_A].status).toBe('started');
		const out2 = await runNodeJson({ credentials: credentials(server), params: security({ securityOptions: { excludeHosts: 'WEB-01' }, dryRun: true }) });
		expect(out2.find((r) => r.host_id === HOST_A)).toMatchObject({ status: 'skipped', reason: 'excluded' });
	});

	it('an error on one host does not stop the others', async () => {
		server.on('POST', '/api/v1/patching/trigger', (req) =>
			(req.json as { host_id: string }).host_id === HOST_A ? { status: 500, json: { error: 'Failed to queue patch' } } : { json: { patch_run_id: 'x-run', run_at: '2026-11-20T10:00:00Z', message: 'Patch queued' } },
		);
		const out = await runNodeJson({ credentials: credentials(server), params: security({ target: 'hostIds', hostIds: [HOST_A, HOST_B, '99999999-9999-4999-8999-999999999999'] }) });
		expect(out.map((r) => [r.host_id, r.status])).toEqual([
			['99999999-9999-4999-8999-999999999999', 'error'],
			[HOST_A, 'error'],
			[HOST_B, 'started'],
		]);
		expect(out[1].message).toBe('PatchMon API error 500: Failed to queue patch');
	});

	it('a selected host on Arch Linux is skipped without a trigger; a refusal by PatchMon is mapped too', async () => {
		const [arch] = await runNodeJson({ credentials: credentials(server), params: security({ target: 'hostIds', hostIds: HOST_ARCH }) });
		expect(arch).toMatchObject({ status: 'skipped', reason: 'os_refused' });
		expect(server.triggers).toHaveLength(0);
		// The package manager is unknown to the session API: PatchMon's 400 is reported as a skip
		server.host(HOST_ARCH).package_manager = '';
		server.on('POST', '/api/v1/patching/trigger', () => ({
			status: 400,
			json: { error: 'Arch Linux does not support partial upgrades, so PatchMon cannot patch selected packages on this host. Use Patch all.' },
		}));
		const [refused] = await runNodeJson({ credentials: credentials(server), params: security({ target: 'hostIds', hostIds: HOST_ARCH }) });
		expect(refused).toMatchObject({ status: 'skipped', reason: 'os_refused' });
	});

	it('summary output', async () => {
		server.addRun(HOST_B, 'queued');
		const out = await runNodeJson({ credentials: credentials(server), params: security({ output: 'summary' }) });
		expect(out).toHaveLength(1);
		expect(out[0]).toMatchObject({
			dry_run: false,
			hosts_considered: 4,
			hosts_started: 1,
			packages_started: 2,
			started: [{ host_id: HOST_A, host_name: 'web-01', packages: ['libssl3', 'openssl'] }],
			errors: [],
		});
		expect((out[0].skipped as Array<{ reason: string }>).map((s) => s.reason).sort()).toEqual(['no_security_updates', 'os_refused', 'run_active']);
	});

	it('host groups and Max Hosts', async () => {
		const out = await runNodeJson({ credentials: credentials(server), params: security({ target: 'groups', groups: GROUP_LAB, dryRun: true }) });
		expect(out.map((r) => r.host_id).sort()).toEqual([HOST_ARCH, HOST_CLEAN].sort());
		const err = await runNodeError({ credentials: credentials(server), params: security({ securityOptions: { maxHosts: 2 } }) });
		expect(err.message).toMatch(/3 hosts have pending security updates, more than Max Hosts \(2\): nothing was started/);
		expect(server.triggers).toHaveLength(0);
	});

	it('fails before starting anything when the sign-in fails', async () => {
		const err = await runNodeError({ credentials: credentials(server, { password: 'wrong-password' }), params: security() });
		expect(err.message).toMatch(/401/);
		expect(server.triggers).toHaveLength(0);
	});

	it('fails before starting anything when the Integration API answers unexpectedly', async () => {
		server.on('GET', '/api/v1/api/hosts/{id}/packages', (_r, p) => (p.id === HOST_B ? { status: 500, json: { error: 'Failed to fetch packages' } } : { json: { packages: [] } }));
		const err = await runNodeError({ credentials: credentials(server), params: security() });
		expect(err.message).toBe('PatchMon API error 500: Failed to fetch packages');
		expect(server.triggers).toHaveLength(0);
		server.on('GET', '/api/v1/api/hosts', () => ({ raw: '<html>login</html>' }));
		expect((await runNodeError({ credentials: credentials(server), params: security() })).message).toMatch(/not a PatchMon JSON response/);
		server.on('GET', '/api/v1/api/hosts', () => ({ json: { items: [] } }));
		expect((await runNodeError({ credentials: credentials(server), params: security() })).message).toMatch(/Unexpected answer from the PatchMon Integration API/);
		expect(server.triggers).toHaveLength(0);
	});
});
