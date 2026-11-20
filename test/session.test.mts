import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FakePatchMon, HOST_A, HOST_B } from './helpers/fakePatchMon.mts';
import { credentials, credentialSaves, integrationOnly, runNodeError, runNodeJson } from './helpers/harness.mts';

let server: FakePatchMon;

beforeAll(async () => {
	server = await new FakePatchMon().start();
});
afterAll(async () => {
	await server.stop();
});
beforeEach(() => server.reset());

const getRuns = { resource: 'patching', operation: 'getRuns', returnAll: true };
const getHosts = { resource: 'host', operation: 'getAll', returnAll: true };

describe('service user session', () => {
	it('signs in once and reuses the stored token in later executions', async () => {
		const stored = credentials(server);
		await runNodeJson({ credentials: stored, params: [getRuns, getRuns] });
		await runNodeJson({ credentials: stored, params: getRuns });
		expect(server.logins).toHaveLength(1);
		expect(stored.sessionToken).toBe(server.issuedTokens[0]);
		const bearer = server.requestsTo('GET', '/api/v1/patching/runs').map((r) => r.headers.authorization);
		expect(bearer).toEqual(Array(3).fill(`Bearer ${server.issuedTokens[0]}`));
		expect(server.crossedCredentials).toEqual([]);
	});

	it('Integration API operations never sign in, even with a service user and no token', async () => {
		const stored = credentials(server);
		const hosts = await runNodeJson({ credentials: stored, params: getHosts });
		expect(hosts).toHaveLength(4);
		expect(server.logins).toHaveLength(0);
		expect(stored.sessionToken).toBeUndefined();
		// ...and a wrong service user password does not break them
		await runNodeJson({ credentials: credentials(server, { password: 'wrong-password' }), params: getHosts });
		expect(server.logins).toHaveLength(0);
	});

	it('signs in again once after a 401 and repeats the request', async () => {
		const stored = credentials(server);
		await runNodeJson({ credentials: stored, params: getRuns });
		server.revokeSessions();
		const saves = credentialSaves.count;
		const out = await runNodeJson({ credentials: stored, params: [getRuns, getRuns] });
		expect(out).toEqual([]);
		expect(server.logins).toHaveLength(2);
		expect(stored.sessionToken).toBe(server.issuedTokens[1]);
		expect(credentialSaves.count).toBe(saves + 1);
	});

	it('uses the same X-Device-ID for every sign-in of the same user and server', async () => {
		const stored = credentials(server);
		await runNodeJson({ credentials: stored, params: getRuns });
		server.revokeSessions();
		await runNodeJson({ credentials: stored, params: getRuns });
		const ids = server.logins.map((r) => r.headers['x-device-id']);
		expect(ids[0]).toBeTruthy();
		expect(ids[1]).toBe(ids[0]);
	});

	it('makes one sign-in attempt per execution when it fails', async () => {
		const err = await runNodeError({ credentials: credentials(server, { password: 'wrong-password' }), params: [getRuns, getRuns, getRuns] });
		expect(err.message).toMatch(/rejected the service user's username or password \(401\)/);
		expect(server.logins).toHaveLength(1);
		const out = await runNodeJson({ credentials: credentials(server, { password: 'wrong-password' }), params: [getRuns, getRuns], continueOnFail: true });
		expect(out.map((o) => o.error)).toEqual([expect.stringMatching(/401/), expect.stringMatching(/401/)]);
		expect(server.logins).toHaveLength(2);
	});

	it('reports MFA and the lockout without leaking secrets', async () => {
		server.userTfa = true;
		const mfa = await runNodeError({ credentials: credentials(server), params: getRuns });
		expect(mfa.message).toMatch(/MFA/);
		server.userTfa = false;
		server.lockedOut = true;
		const locked = await runNodeError({ credentials: credentials(server), params: getRuns });
		expect(locked.message).toMatch(/429/);
		expect(locked.description).toMatch(/wait 120 s/);
	});

	it('refuses session operations when the credential has no service user', async () => {
		const err = await runNodeError({ credentials: integrationOnly(server), params: { resource: 'patching', operation: 'triggerPatch', hostId: HOST_A, patchType: 'patch_all' } });
		expect(err.message).toMatch(/needs the service user/);
		expect(server.requests).toHaveLength(0);
	});

	it('missing permissions never make the sign-in fail', async () => {
		server.permissions = new Set(['can_view_hosts']);
		const stored = credentials(server);
		expect(await runNodeJson({ credentials: stored, params: getRuns })).toEqual([]);
		expect(stored.sessionPermissions).toBe('can_view_hosts');
		server.permissions = new Set();
		const none = credentials(server);
		const err = await runNodeError({ credentials: none, params: getRuns });
		// Signed in; PatchMon itself refuses the read
		expect(none.sessionToken).toBe(server.issuedTokens.at(-1));
		expect(err.message).toBe('PatchMon API error 403: Insufficient permissions');
		expect(err.description).toMatch(/needs the permission can_view_hosts/);
	});

	it('operations that change PatchMon check can_manage_patching before calling the server', async () => {
		server.permissions = new Set(['can_view_hosts']);
		const stored = credentials(server);
		const run = server.addRun(HOST_A, 'pending_approval');
		const cases: Array<[Record<string, unknown>, string]> = [
			[{ resource: 'patching', operation: 'triggerPatch', hostId: HOST_A, patchType: 'patch_all' }, 'Trigger Patch'],
			[{ resource: 'patching', operation: 'triggerPatch', hostId: HOST_A, patchType: 'patch_package', packageNames: 'openssl', dryRun: true }, 'Trigger Patch'],
			[{ resource: 'patching', operation: 'approveRun', runId: run.id }, 'Approve Run'],
			[{ resource: 'patching', operation: 'cancelRun', runId: run.id }, 'Cancel Run'],
			[{ resource: 'patching', operation: 'patchSecurityUpdates', target: 'all' }, 'Patch Security Updates'],
		];
		for (const [params, what] of cases) {
			const err = await runNodeError({ credentials: stored, params });
			expect(err.message).toBe(`${what} needs the permission can_manage_patching, which the service user's role does not have: nothing was changed in PatchMon`);
			expect(err.description).toMatch(/Give can_manage_patching to the role/);
		}
		const sent = server.requests.map((r) => `${r.method} ${r.path}`);
		expect(sent.filter((r) => r.startsWith('POST /api/v1/patching'))).toEqual([]);
		// Patch Security Updates fails before reading hosts or packages
		expect(sent.filter((r) => r.includes('/api/v1/api/'))).toEqual([]);
		expect(run.status).toBe('pending_approval');
	});

	it('Patch Security Updates with Dry Run works without can_manage_patching', async () => {
		server.permissions = new Set(['can_view_hosts']);
		const out = await runNodeJson({ credentials: credentials(server), params: { resource: 'patching', operation: 'patchSecurityUpdates', target: 'all', dryRun: true } });
		expect(out.filter((r) => r.status === 'would_start')).toHaveLength(2);
		expect(server.requestsTo('GET', '/api/v1/permissions/user-permissions')).toHaveLength(1);
	});

	it('reads the permissions once per execution', async () => {
		const stored = credentials(server);
		const trigger = { resource: 'patching', operation: 'triggerPatch', patchType: 'patch_all' };
		await runNodeJson({ credentials: stored, params: [{ ...trigger, hostId: HOST_A }, { ...trigger, hostId: HOST_B }] });
		expect(server.triggers).toHaveLength(2);
		// one read by the sign-in (stored for the credential test), one by the execution
		expect(server.requestsTo('GET', '/api/v1/permissions/user-permissions')).toHaveLength(2);
		// A role changed in PatchMon is seen by the next execution
		server.permissions = new Set(['can_view_hosts']);
		const err = await runNodeError({ credentials: stored, params: { ...trigger, hostId: HOST_A } });
		expect(err.message).toMatch(/needs the permission can_manage_patching/);
	});
});
