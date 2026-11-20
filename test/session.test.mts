import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { FakePatchMon, HOST_A } from './helpers/fakePatchMon.mts';
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

	it('reports MFA, missing permissions and the lockout without leaking secrets', async () => {
		server.userTfa = true;
		const mfa = await runNodeError({ credentials: credentials(server), params: getRuns });
		expect(mfa.message).toMatch(/MFA/);
		server.userTfa = false;
		server.permissions = new Set(['can_view_hosts']);
		expect((await runNodeError({ credentials: credentials(server), params: getRuns })).message).toMatch(/can_manage_patching/);
		server.permissions = new Set(['can_view_hosts', 'can_manage_patching']);
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

	it('explains a 403 from a missing permission with the permission name', async () => {
		const stored = credentials(server);
		await runNodeJson({ credentials: stored, params: getRuns });
		server.permissions = new Set(['can_view_hosts']);
		const err = await runNodeError({
			credentials: stored,
			params: { resource: 'patching', operation: 'cancelRun', runId: server.addRun(HOST_A, 'queued').id },
		});
		expect(err.message).toBe('PatchMon API error 403: Insufficient permissions');
		expect(err.description).toMatch(/can_manage_patching/);
	});
});
