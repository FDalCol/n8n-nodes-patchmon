import type { IDataObject } from 'n8n-workflow';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FakePatchMon, HOST_A, HOST_B, HOST_CLEAN, PASSWORD, TOKEN_SECRET } from './helpers/fakePatchMon.mts';
import { credentials, integrationOnly, poll } from './helpers/harness.mts';

let server: FakePatchMon;

beforeAll(async () => {
	server = await new FakePatchMon().start();
});
afterAll(async () => {
	await server.stop();
});
beforeEach(() => server.reset());

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

describe('New Security Updates', () => {
	it('first poll stores the state without events, then fires once per new update', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'newSecurityUpdates' };
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		server.host(HOST_B).packages.push({ id: 'p-x', name: 'sudo', current_version: '1', available_version: '2', needs_update: true, is_security_update: true });
		const items = await poll({ credentials: integrationOnly(server), params, staticData });
		expect(items).toHaveLength(1);
		expect(items![0]).toMatchObject({
			event: 'newSecurityUpdates',
			host_id: HOST_B,
			host_name: 'db-01',
			security_updates_count: 2,
			new_security_updates: [{ name: 'sudo', current_version: '1', available_version: '2', category: 'net' }],
		});
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		// A newer version of an already known package is a new update
		server.host(HOST_A).packages[0].available_version = '1.0.2';
		const again = await poll({ credentials: integrationOnly(server), params, staticData });
		expect(again!.map((i) => (i.new_security_updates as IDataObject[]).map((p) => p.name))).toEqual([['openssl']]);
		expect(server.logins).toHaveLength(0);
	});

	it('an update that was installed and comes back fires again', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'newSecurityUpdates', filters: { hostIds: HOST_B } };
		await poll({ credentials: integrationOnly(server), params, staticData });
		const saved = server.host(HOST_B).packages;
		server.host(HOST_B).packages = [];
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		server.host(HOST_B).packages = saved;
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toHaveLength(1);
	});

	it('keeps one fingerprint per host: state bounded by hosts, no repeated events with many updates', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'newSecurityUpdates', maxHosts: 1000 };
		const many = (prefix: string, n: number) =>
			Array.from({ length: n }, (_, i) => ({ id: `${prefix}-${i}`, name: `${prefix}-pkg-${i}`, current_version: '1', available_version: '2', needs_update: true, is_security_update: true }));
		server.host(HOST_A).packages = many('a', 400);
		server.host(HOST_B).packages = many('b', 30);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		const hosts = staticData.hosts as Record<string, { f: string; p: string[] }>;
		expect(Object.keys(hosts)).toHaveLength(3);
		expect(Object.values(hosts).map((h) => h.p.length).sort((x, y) => x - y)).toEqual([1, 30, 400]);
		expect(Object.values(hosts).every((h) => h.p.every((k) => k.length <= 8))).toBe(true);
		expect(staticData.seen).toBeUndefined();
		// Unchanged updates never fire again
		for (let i = 0; i < 3; i++) expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		// One new update on the large host: only that one is reported
		server.host(HOST_A).packages = [...many('a', 400), ...many('z', 1)];
		const items = await poll({ credentials: integrationOnly(server), params, staticData });
		expect(items).toHaveLength(1);
		expect(items![0]).toMatchObject({ host_id: HOST_A, security_updates_count: 401 });
		expect((items![0].new_security_updates as IDataObject[]).map((p) => p.name)).toEqual(['z-pkg-0']);
		// An installed update changes the fingerprint but brings nothing new: no event
		server.host(HOST_B).packages = many('b', 29);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
	});

	it('keeps at most 1000 package hashes per host', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'newSecurityUpdates', filters: { hostIds: HOST_A } };
		server.host(HOST_A).packages = Array.from({ length: 1200 }, (_, i) => ({
			id: `p-${i}`,
			name: `pkg-${i}`,
			current_version: '1',
			available_version: '2',
			needs_update: true,
			is_security_update: true,
		}));
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		const [entry] = Object.values(staticData.hosts as Record<string, { p: string[] }>);
		expect(entry.p).toHaveLength(1000);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
	});

	it('filters by host and group; test mode returns a real example and keeps the state', async () => {
		const staticData: IDataObject = {};
		const sample = await poll({ credentials: integrationOnly(server), params: { event: 'newSecurityUpdates', filters: { groups: 'Lab' } }, staticData, mode: 'manual' });
		expect(sample).toHaveLength(1);
		expect(sample![0]).toMatchObject({ host_name: 'arch-lab', new_security_updates: [expect.objectContaining({ name: 'glibc' })] });
		expect(staticData.hosts).toBeUndefined();
		expect(server.requests[0].query.get('hostgroup')).toBe('Lab');
	});
});

describe('Patch Run Finished / Failed', () => {
	it('fires for runs that completed after the first poll, once', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'patchRunFinished' };
		const creds = credentials(server);
		server.addRun(HOST_A, 'completed');
		expect(await poll({ credentials: creds, params, staticData })).toBeNull();
		const run = server.addRun(HOST_B, 'completed', { package_names: ['openssh-server'] });
		server.addRun(HOST_B, 'failed');
		const items = await poll({ credentials: creds, params, staticData });
		expect(items).toEqual([
			expect.objectContaining({ event: 'patchRunFinished', run_id: run.id, host_id: HOST_B, host_name: 'db-01', status: 'completed', package_names: ['openssh-server'] }),
		]);
		expect(items![0].shell_output).toBeUndefined();
		expect(await poll({ credentials: creds, params, staticData })).toBeNull();
		expect(server.logins).toHaveLength(1);
	});

	it('failed covers failed, timed_out and agent_disconnected, without dry runs by default', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'patchRunFailed' };
		await poll({ credentials: credentials(server), params, staticData });
		server.addRun(HOST_A, 'failed', { error_message: 'apt failed' });
		server.addRun(HOST_B, 'timed_out');
		server.addRun(HOST_CLEAN, 'agent_disconnected');
		server.addRun(HOST_A, 'failed', { dry_run: true });
		server.addRun(HOST_A, 'cancelled');
		const items = await poll({ credentials: credentials(server), params, staticData });
		expect(items!.map((i) => i.status).sort()).toEqual(['agent_disconnected', 'failed', 'timed_out']);
		expect(items!.find((i) => i.status === 'failed')).toMatchObject({ error_message: 'apt failed' });
		server.addRun(HOST_B, 'failed', { dry_run: true });
		const withDry = await poll({ credentials: credentials(server), params: { event: 'patchRunFailed', filters: { includeDryRuns: true } }, staticData });
		expect(withDry!.map((i) => i.dry_run)).toEqual([true, true]);
	});

	it('filters by host and group', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'patchRunFinished', filters: { groups: 'Lab' } };
		await poll({ credentials: credentials(server), params, staticData });
		server.addRun(HOST_A, 'completed');
		server.addRun(HOST_CLEAN, 'completed');
		const items = await poll({ credentials: credentials(server), params, staticData });
		expect(items!.map((i) => i.host_id)).toEqual([HOST_CLEAN]);
		const single = { event: 'patchRunFinished', filters: { hostIds: HOST_A } };
		const s2: IDataObject = {};
		await poll({ credentials: credentials(server), params: single, staticData: s2 });
		expect(server.requestsTo('GET', '/api/v1/patching/runs').at(-1)!.query.get('host_id')).toBe(HOST_A);
	});

	it('test mode returns the latest real run', async () => {
		const run = server.addRun(HOST_A, 'completed');
		const items = await poll({ credentials: credentials(server), params: { event: 'patchRunFinished' }, staticData: {}, mode: 'manual' });
		expect(items).toEqual([expect.objectContaining({ run_id: run.id })]);
	});

	it('needs the service user', async () => {
		await expect(poll({ credentials: integrationOnly(server), params: { event: 'patchRunFinished' }, staticData: {} })).rejects.toThrow(/needs the service user/);
	});

	it('after a 401 sign-in it waits 1 h, doubled up to 24 h, and reports every failed attempt', async () => {
		const staticData: IDataObject = {};
		const bad = credentials(server, { password: 'wrong-password' });
		const params = { event: 'patchRunFailed' };
		const pause = () => staticData.signInPause as IDataObject;
		const hoursLeft = () => (Date.parse(String(pause().until)) - Date.now()) / 3_600_000;
		const expire = () => (pause().until = new Date(Date.now() - 1000).toISOString());

		const first = await poll({ credentials: bad, params, staticData }).catch((e: Error & { description?: string }) => e);
		expect((first as Error).message).toMatch(/401/);
		expect((first as { description?: string }).description).toMatch(/Next sign-in attempt after \d{4}-/);
		expect(pause()).toMatchObject({ status: 401, failures: 1 });
		expect(hoursLeft()).toBeGreaterThan(0.99);
		expect(hoursLeft()).toBeLessThanOrEqual(1);
		// During the wait: no sign-in, no error
		expect(await poll({ credentials: bad, params, staticData })).toBeNull();
		expect(server.logins).toHaveLength(1);

		for (const [failures, hours] of [[2, 2], [3, 4], [4, 8], [5, 16], [6, 24], [7, 24]] as const) {
			expire();
			await expect(poll({ credentials: bad, params, staticData })).rejects.toThrow(/401/);
			expect(pause().failures).toBe(failures);
			expect(hoursLeft()).toBeGreaterThan(hours - 0.01);
			expect(hoursLeft()).toBeLessThanOrEqual(hours);
		}
		expect(server.logins).toHaveLength(7);
		const stored = JSON.stringify(staticData);
		for (const secret of ['wrong-password', PASSWORD, TOKEN_SECRET]) expect(stored).not.toContain(secret);

		// A corrected credential (n8n stores a new fingerprint when it is saved and tested) is tried at once
		expect(await poll({ credentials: credentials(server, { sessionTokenFingerprint: 'changed' }), params, staticData })).toBeNull();
		expect(server.logins).toHaveLength(8);
		expect(staticData.signInPause).toBeUndefined();
	});

	it('after a 429 sign-in it waits as long as PatchMon asks', async () => {
		const staticData: IDataObject = {};
		server.lockedOut = true;
		const params = { event: 'patchRunFinished' };
		await expect(poll({ credentials: credentials(server), params, staticData })).rejects.toThrow(/429/);
		expect(await poll({ credentials: credentials(server), params, staticData })).toBeNull();
		expect(server.logins).toHaveLength(1);
		const until = Date.parse(String((staticData.signInPause as IDataObject).until));
		expect(until - Date.now()).toBeGreaterThan(100_000);
		(staticData.signInPause as IDataObject).until = new Date(Date.now() - 1000).toISOString();
		server.lockedOut = false;
		expect(await poll({ credentials: credentials(server), params, staticData })).toBeNull();
		expect(server.logins).toHaveLength(2);
	});
});

describe('Host Offline', () => {
	it('fires once when a host stops reporting and again only after it came back', async () => {
		const staticData: IDataObject = {};
		const params = { event: 'hostOffline', offlineMinutes: 60 };
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		server.host(HOST_B).last_update = minutesAgo(90);
		const items = await poll({ credentials: integrationOnly(server), params, staticData });
		expect(items).toEqual([expect.objectContaining({ event: 'hostOffline', host_id: HOST_B, is_offline: true, minutes_since_last_contact: 90, offline_after_minutes: 60 })]);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		server.host(HOST_B).last_update = minutesAgo(1);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		server.host(HOST_B).last_update = minutesAgo(61);
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toHaveLength(1);
	});

	it('hosts already offline at activation do not fire; pending hosts are ignored', async () => {
		const staticData: IDataObject = {};
		server.host(HOST_A).last_update = minutesAgo(500);
		server.host(HOST_CLEAN).status = 'pending';
		server.host(HOST_CLEAN).last_update = minutesAgo(900);
		const params = { event: 'hostOffline', offlineMinutes: 120 };
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
		expect(await poll({ credentials: integrationOnly(server), params, staticData })).toBeNull();
	});

	it('test mode: offline hosts, else the host with the oldest contact', async () => {
		const sample = await poll({ credentials: integrationOnly(server), params: { event: 'hostOffline', offlineMinutes: 60 }, staticData: {}, mode: 'manual' });
		expect(sample).toEqual([expect.objectContaining({ host_name: 'clean-01', is_offline: false })]);
		server.host(HOST_A).last_update = minutesAgo(70);
		const offline = await poll({ credentials: integrationOnly(server), params: { event: 'hostOffline', offlineMinutes: 60 }, staticData: {}, mode: 'manual' });
		expect(offline).toEqual([expect.objectContaining({ host_id: HOST_A, is_offline: true })]);
	});

	it('validates limits that come from expressions', async () => {
		await expect(poll({ credentials: integrationOnly(server), params: { event: 'hostOffline', offlineMinutes: 1 }, staticData: {} })).rejects.toThrow(/between 5 and 10080/);
		await expect(poll({ credentials: integrationOnly(server), params: { event: 'newSecurityUpdates', maxHosts: 5000 }, staticData: {} })).rejects.toThrow(/between 1 and 1000/);
		await expect(poll({ credentials: integrationOnly(server), params: { event: 'hostOffline', filters: { hostIds: 'web-01' } }, staticData: {} })).rejects.toThrow(/UUID/);
	});
});
