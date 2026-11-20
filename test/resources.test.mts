import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FakePatchMon, GROUP_LAB, GROUP_PROD, HOST_A, HOST_B, POLICY_ID } from './helpers/fakePatchMon.mts';
import { credentials, integrationOnly, runNode, runNodeError, runNodeJson } from './helpers/harness.mts';

let server: FakePatchMon;

beforeAll(async () => {
	server = await new FakePatchMon().start();
});
afterAll(async () => {
	await server.stop();
});
beforeEach(() => server.reset());

const host = (params: Record<string, unknown>) => ({ resource: 'host', ...params });

describe('Host (Integration API)', () => {
	it('Get Many returns every host with stats, filtered on the client', async () => {
		const all = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true }) });
		expect(all.map((h) => h.friendly_name)).toEqual(['web-01', 'db-01', 'arch-lab', 'clean-01']);
		expect(server.requests[0].query.get('include')).toBe('stats');
		const sec = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true, filters: { updateState: 'security_required', osType: 'ubu' } }) });
		expect(sec.map((h) => h.id)).toEqual([HOST_A]);
		const reboot = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true, filters: { needsReboot: true } }) });
		expect(reboot.map((h) => h.id)).toEqual([HOST_B]);
		const limited = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', limit: 2, splitIntoItems: false }) });
		expect(limited).toHaveLength(1);
		expect((limited[0].data as unknown[]).length).toBe(2);
	});

	it('Get Many passes host groups (IDs or names) to PatchMon', async () => {
		const prod = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true, filters: { groups: 'Production' } }) });
		expect(prod).toHaveLength(2);
		const lab = await runNodeJson({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true, filters: { groups: `${GROUP_LAB}` } }) });
		expect(lab).toHaveLength(2);
		expect(server.requests.map((r) => r.query.get('hostgroup'))).toEqual(['Production', GROUP_LAB]);
	});

	it('Get, Get Stats, Get System and Get Network', async () => {
		const creds = integrationOnly(server);
		const [info, stats, system, network] = await runNodeJson({
			credentials: creds,
			params: ['get', 'getStats', 'getSystem', 'getNetwork'].map((operation) => host({ operation, hostId: HOST_A })),
		});
		expect(info).toMatchObject({ id: HOST_A, agent_version: '2.1.8' });
		expect(stats).toMatchObject({ security_updates: 2, outdated_packages: 3 });
		expect(system).toMatchObject({ architecture: 'x86_64' });
		expect(network).toMatchObject({ gateway_ip: '192.0.2.1' });
		expect(server.requests.map((r) => r.path)).toEqual([
			`/api/v1/api/hosts/${HOST_A}/info`,
			`/api/v1/api/hosts/${HOST_A}/stats`,
			`/api/v1/api/hosts/${HOST_A}/system`,
			`/api/v1/api/hosts/${HOST_A}/network`,
		]);
	});

	it('Get Packages: all, only with updates, only security updates, name filter', async () => {
		const creds = integrationOnly(server);
		const run = async (packageFilters: Record<string, unknown>) =>
			(await runNodeJson({ credentials: creds, params: host({ operation: 'getPackages', hostId: HOST_A, returnAll: true, packageFilters }) })).map((p) => p.name);
		expect(await run({})).toEqual(['openssl', 'libssl3', 'vim', 'bash']);
		expect(await run({ onlyWithUpdates: true })).toEqual(['openssl', 'libssl3', 'vim']);
		expect(await run({ onlySecurity: true })).toEqual(['openssl', 'libssl3']);
		expect(await run({ onlySecurity: true, name: 'LIBSSL' })).toEqual(['libssl3']);
		expect(server.requests.map((r) => r.query.get('updates_only'))).toEqual([null, 'true', 'true', 'true']);
		const one = await runNodeJson({ credentials: creds, params: host({ operation: 'getPackages', hostId: HOST_A, limit: 1 }) });
		expect(one[0]).toMatchObject({ name: 'openssl', is_security_update: true, host: { id: HOST_A, friendly_name: 'web-01' } });
	});

	it('validates the host ID before sending and reports 404', async () => {
		const bad = await runNodeError({ credentials: integrationOnly(server), params: host({ operation: 'get', hostId: '../patching' }) });
		expect(bad.message).toBe('Host ID must be a UUID');
		expect(server.requests).toHaveLength(0);
		const missing = await runNodeError({ credentials: integrationOnly(server), params: host({ operation: 'get', hostId: '99999999-9999-4999-8999-999999999999' }) });
		expect(missing.message).toBe('PatchMon API error 404: Host not found');
	});

	it('reports 401 and 403 of the Integration API', async () => {
		const wrong = await runNodeError({ credentials: integrationOnly(server, { tokenSecret: 'nope' }), params: host({ operation: 'getAll', returnAll: true }) });
		expect(wrong.message).toBe('PatchMon API error 401: Invalid API secret');
		expect(wrong.description).toMatch(/Token Key or Token Secret/);
		server.scopes = [];
		const scope = await runNodeError({ credentials: integrationOnly(server), params: host({ operation: 'getAll', returnAll: true }) });
		expect(scope.message).toBe('PatchMon API error 403: Access denied: This API key does not have permission to get host');
		expect(scope.description).toMatch(/host: get/);
	});
});

describe('Host Group, Repository, Patch Policy (session)', () => {
	it('Host Group: Get Many, Get, Get Hosts', async () => {
		const creds = credentials(server);
		const groups = await runNodeJson({ credentials: creds, params: { resource: 'hostGroup', operation: 'getAll', returnAll: true } });
		expect(groups.map((g) => g.name)).toEqual(['Production', 'Lab']);
		const [one] = await runNodeJson({ credentials: creds, params: { resource: 'hostGroup', operation: 'get', groupId: GROUP_PROD } });
		expect(one).toEqual({ id: GROUP_PROD, name: 'Production' });
		const hosts = await runNodeJson({ credentials: creds, params: { resource: 'hostGroup', operation: 'getHosts', groupId: GROUP_PROD, returnAll: true } });
		expect(hosts.map((h) => h.friendly_name)).toEqual(['web-01', 'db-01']);
	});

	it('Repository: Get Many pages through the results, Get, Get by Host', async () => {
		const creds = credentials(server);
		const all = await runNodeJson({ credentials: creds, params: { resource: 'repository', operation: 'getAll', returnAll: true } });
		expect(all.map((r) => r.id)).toEqual(['repo-1', 'repo-2', 'repo-3', 'repo-4', 'repo-5', 'repo-6', 'repo-7']);
		expect(server.requestsTo('GET', '/api/v1/repositories').map((r) => r.query.get('offset'))).toEqual(['0', '3', '6']);
		const some = await runNodeJson({ credentials: creds, params: { resource: 'repository', operation: 'getAll', limit: 2, filters: { status: 'active', type: 'secure' } } });
		expect(some.map((r) => r.id)).toEqual(['repo-1', 'repo-3']);
		const [one] = await runNodeJson({ credentials: creds, params: { resource: 'repository', operation: 'get', repositoryId: 'repo-2' } });
		expect(one).toMatchObject({ id: 'repo-2' });
		const byHost = await runNodeJson({ credentials: creds, params: { resource: 'repository', operation: 'getByHost', hostId: HOST_A, returnAll: true } });
		expect(byHost).toHaveLength(2);
	});

	it('Patch Policy: Get Many and Get', async () => {
		const creds = credentials(server);
		const all = await runNodeJson({ credentials: creds, params: { resource: 'patchPolicy', operation: 'getAll', returnAll: true } });
		expect(all).toEqual([expect.objectContaining({ id: POLICY_ID, patch_delay_type: 'fixed_time' })]);
		const [one] = await runNodeJson({ credentials: creds, params: { resource: 'patchPolicy', operation: 'get', policyId: POLICY_ID } });
		expect(one).toMatchObject({ name: 'Weekend window', assignments: [] });
	});
});

describe('Patching reads', () => {
	it('Get Runs pages through results and applies filters and sort', async () => {
		for (let i = 0; i < 5; i++) server.addRun(HOST_A, 'completed');
		server.addRun(HOST_B, 'failed');
		const creds = credentials(server);
		const all = await runNodeJson({ credentials: creds, params: { resource: 'patching', operation: 'getRuns', returnAll: true } });
		expect(all).toHaveLength(6);
		const some = await runNodeJson({
			credentials: creds,
			params: { resource: 'patching', operation: 'getRuns', limit: 3, runFilters: { hostId: HOST_A, status: 'completed' }, runSort: { sortBy: 'completed_at', sortDir: 'asc' }, includeOutput: false },
		});
		expect(some).toHaveLength(3);
		expect(some[0].shell_output).toBeUndefined();
		const q = server.requestsTo('GET', '/api/v1/patching/runs').at(-1)!.query;
		expect(Object.fromEntries(q)).toEqual({ host_id: HOST_A, status: 'completed', sort_by: 'completed_at', sort_dir: 'asc', limit: '3', offset: '0' });
	});

	it('Get Active Runs, Get Run and Preview Run', async () => {
		const run = server.addRun(HOST_A, 'scheduled');
		server.addRun(HOST_B, 'validated', { dry_run: true });
		server.autoAdvance = false;
		const creds = credentials(server);
		const active = await runNodeJson({ credentials: creds, params: { resource: 'patching', operation: 'getActiveRuns', returnAll: true } });
		expect(active.map((r) => [r.status, r.blocks_new_runs])).toEqual([
			['scheduled', true],
			['validated', false],
		]);
		const forB = await runNodeJson({ credentials: creds, params: { resource: 'patching', operation: 'getActiveRuns', returnAll: true, activeHostId: HOST_B } });
		expect(forB).toHaveLength(1);
		const [one] = await runNodeJson({ credentials: creds, params: { resource: 'patching', operation: 'getRun', runId: run.id } });
		expect(one).toMatchObject({ id: run.id, status: 'scheduled', shell_output: 'Reading package lists...' });
		const [preview] = await runNodeJson({ credentials: creds, params: { resource: 'patching', operation: 'previewRun', hostId: HOST_A } });
		expect(preview).toMatchObject({ host_id: HOST_A, patch_delay_type: 'immediate' });
	});
});

describe('item handling', () => {
	it('continueOnFail returns { error } with pairedItem and keeps going', async () => {
		const out = await runNode({
			credentials: integrationOnly(server),
			continueOnFail: true,
			params: [host({ operation: 'get', hostId: 'nope' }), host({ operation: 'get', hostId: HOST_A })],
		});
		expect(out[0]).toEqual({ json: { error: 'Host ID must be a UUID' }, pairedItem: { item: 0 } });
		expect(out[1].json).toMatchObject({ id: HOST_A });
		expect(out[1].pairedItem).toEqual({ item: 1 });
	});

	it('every output item is paired with its input item', async () => {
		const out = await runNode({ credentials: integrationOnly(server), params: [host({ operation: 'getAll', returnAll: true }), host({ operation: 'getStats', hostId: HOST_B })] });
		expect(out.map((i) => i.pairedItem)).toEqual([...Array(4).fill({ item: 0 }), { item: 1 }]);
	});
});
