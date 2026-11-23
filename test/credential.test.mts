import type { IHttpRequestOptions } from 'n8n-workflow';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { sessionTokenFingerprint } from '../nodes/PatchMon/shared/auth';
import { FakePatchMon, PASSWORD, TOKEN_KEY, TOKEN_SECRET, Trap, USERNAME } from './helpers/fakePatchMon.mts';
import { credentials, credentialType, evalCredentialExpression, integrationOnly, runCredentialTest } from './helpers/harness.mts';

let server: FakePatchMon;
let trap: Trap;

beforeAll(async () => {
	server = await new FakePatchMon().start();
	trap = await new Trap().start();
});
afterAll(async () => {
	await server.stop();
	await trap.stop();
});
beforeEach(() => server.reset());

const authenticate = credentialType.authenticate as (c: Record<string, unknown>, o: IHttpRequestOptions) => Promise<IHttpRequestOptions>;
const BASIC = `Basic ${Buffer.from(`${TOKEN_KEY}:${TOKEN_SECRET}`).toString('base64')}`;
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.abcdefghijklmnop0123';

describe('credential', () => {
	it('has the expected fields, with secrets in password fields', () => {
		const byName = Object.fromEntries(credentialType.properties.map((p) => [p.name, p]));
		expect(Object.keys(byName)).toEqual([
			'baseUrl',
			'tokenKey',
			'tokenSecret',
			'serviceUserNotice',
			'username',
			'password',
			'sessionToken',
			'sessionTokenFingerprint',
			'sessionPermissions',
		]);
		expect(credentialType.name).toBe('patchMonApi');
		expect(byName.sessionPermissions).toMatchObject({ type: 'hidden', default: '', typeOptions: { password: true } });
		expect(credentialType.displayName).toBe('PatchMon API');
		expect(byName.tokenSecret.typeOptions).toEqual({ password: true });
		expect(byName.password.typeOptions).toEqual({ password: true });
		expect(byName.username.required).toBeFalsy();
		expect(byName.sessionToken).toMatchObject({ type: 'hidden', default: '', typeOptions: { expirable: true, password: true } });
		expect(byName.sessionTokenFingerprint).toMatchObject({ type: 'hidden', typeOptions: { password: true } });
		expect(typeof credentialType.preAuthentication).toBe('function');
	});

	it('sends Basic Auth only to the Integration API and Bearer only to session routes of the Base URL', async () => {
		const base = 'https://pm.example.com/sub';
		const token = JWT;
		const creds = {
			baseUrl: `${base}/`,
			tokenKey: TOKEN_KEY,
			tokenSecret: TOKEN_SECRET,
			username: USERNAME,
			password: PASSWORD,
			sessionToken: token,
			sessionTokenFingerprint: sessionTokenFingerprint(base, USERNAME, PASSWORD, token),
		};
		const header = async (url: string, baseURL?: string) => (await authenticate(creds, { url, baseURL })).headers?.Authorization;
		// The credential test marker is removed and never makes an ordinary request fail
		const marked = await authenticate({ ...creds, sessionPermissions: 'can_view_hosts' }, { url: `${base}/api/v1/api/hosts`, headers: { 'X-N8n-PatchMon-Credential-Test': '1', Accept: 'x' } });
		expect(marked.headers).toEqual({ Accept: 'x', Authorization: BASIC });
		await expect(authenticate(creds, { url: `${base}/api/v1/api/hosts`, headers: { 'x-n8n-patchmon-credential-test': '1' } })).rejects.toThrow(/can_view_hosts/);
		expect(await header(`${base}/api/v1/api/hosts`)).toBe(BASIC);
		expect(await header('/api/v1/api/hosts', base)).toBe(BASIC);
		expect(await header(`${base}/api/v1/patching/runs`)).toBe(`Bearer ${token}`);
		// Another host, another prefix, outside /api/v1, traversal: nothing
		for (const url of [
			'https://evil.example/api/v1/api/hosts',
			'https://pm.example.com/api/v1/patching/runs',
			`${base}/health`,
			`${base}/api/v1/patching/../api/hosts`,
			`${base}/api/v1/patching/%2e%2e/api/hosts`,
			`${base}/api/v1/api%2fhosts`,
		]) {
			expect(await header(url), url).toBeUndefined();
		}
		// A token issued for another password or Base URL is never sent
		expect((await authenticate({ ...creds, password: 'other' }, { url: `${base}/api/v1/patching/runs` })).headers).toBeUndefined();
		expect((await authenticate({ ...creds, baseUrl: 'https://other.example' }, { url: 'https://other.example/api/v1/patching/runs' })).headers).toBeUndefined();
		// Without a service user the session routes get nothing, the Integration API still works
		const noUser = { baseUrl: base, tokenKey: TOKEN_KEY, tokenSecret: TOKEN_SECRET, sessionToken: token };
		expect((await authenticate(noUser, { url: `${base}/api/v1/patching/runs` })).headers).toBeUndefined();
		expect(await authenticate(noUser, { url: `${base}/api/v1/api/hosts` }).then((o) => o.headers?.Authorization)).toBe(BASIC);
		// A key with a colon or control characters is never sent
		expect((await authenticate({ ...noUser, tokenKey: 'a:b' }, { url: `${base}/api/v1/api/hosts` })).headers).toBeUndefined();
	});

	it('the test request uses the Integration API and only http(s) base URLs', () => {
		const req = credentialType.test.request;
		expect(req.url).toBe('/api/v1/api/hosts');
		expect(req.method).toBe('GET');
		expect(req.disableFollowRedirect).toBe(true);
		expect(req.maxResponseBodyBytes).toBe(16 * 1024 * 1024);
		expect(req.timeout).toBe(30_000);
		expect(evalCredentialExpression(req.baseURL, { baseUrl: 'https://pm.example.com//' })).toBe('https://pm.example.com');
		for (const bad of ['ftp://x', 'http://u:p@x', 'http://x/?a=1', 'http://x/#f', 'javascript:alert(1)', '']) {
			expect(String(evalCredentialExpression(req.baseURL, { baseUrl: bad })), bad).toMatch(/\.invalid$/);
		}
	});

	it('succeeds with the Integration API token alone, without signing in', async () => {
		expect(await runCredentialTest(integrationOnly(server))).toEqual({ status: 'OK', message: 'Connection successful!' });
		expect(server.logins).toHaveLength(0);
		expect(server.requests[0].headers.authorization).toBe(BASIC);
	});

	it('with a service user: signs in, checks permissions and keeps a valid token', async () => {
		const stored = credentials(server);
		expect(await runCredentialTest(stored)).toEqual({ status: 'OK', message: 'Connection successful!' });
		expect(server.logins).toHaveLength(1);
		expect(server.logins[0].json).toEqual({ username: USERNAME, password: PASSWORD });
		expect(server.logins[0].headers['x-device-id']).toMatch(/^n8n-[a-z0-9]+$/);
		expect(server.requestsTo('GET', '/api/v1/permissions/user-permissions')).toHaveLength(1);
		expect(stored.sessionToken).toBe(server.issuedTokens[0]);
		// A second test reuses the stored token
		expect((await runCredentialTest(stored)).status).toBe('OK');
		expect(server.logins).toHaveLength(1);
		expect(server.crossedCredentials).toEqual([]);
	});

	it('explains 401 and 403 of the Integration API', async () => {
		expect((await runCredentialTest(integrationOnly(server, { tokenSecret: 'wrong-secret' }))).message).toMatch(/^Integration API authentication failed \(401\)/);
		server.scopes = [];
		expect((await runCredentialTest(integrationOnly(server))).message).toMatch(/needs the scope host: get/);
	});

	it('explains a wrong password, MFA, missing permissions, SSO-only and lockout', async () => {
		const wrong = await runCredentialTest(credentials(server, { password: 'wrong-password' }));
		expect(wrong.message).toMatch(/rejected the service user's username or password \(401\): Invalid credentials/);
		expect(wrong.message).not.toContain('wrong-password');

		server.userTfa = true;
		const mfa = await runCredentialTest(credentials(server));
		expect(mfa.message).toMatch(/two-factor authentication \(MFA\) enabled/);
		expect(mfa.message).not.toContain('ticket-should-not-leak');
		server.userTfa = false;

		server.localAuthDisabled = true;
		expect((await runCredentialTest(credentials(server))).message).toMatch(/refused the sign-in \(403\): Local authentication is disabled/);
		server.localAuthDisabled = false;

		server.lockedOut = true;
		expect((await runCredentialTest(credentials(server))).message).toMatch(/Too many sign-in attempts.*\(429\)/);
		server.lockedOut = false;

		server.passwordChangeRequired = true;
		expect((await runCredentialTest(credentials(server))).message).toMatch(/replace its temporary password/);
		server.passwordChangeRequired = false;

		server.tfaEnrolmentRequired = true;
		expect((await runCredentialTest(credentials(server))).message).toMatch(/set up two-factor authentication first/);
	});

	it('fails only when the service user lacks can_view_hosts; can_manage_patching is optional', async () => {
		server.permissions = new Set(['can_view_hosts']);
		const readOnly = credentials(server);
		expect(await runCredentialTest(readOnly)).toEqual({ status: 'OK', message: 'Connection successful!' });
		expect(readOnly.sessionPermissions).toBe('can_view_hosts');

		server.permissions = new Set(['can_manage_patching']);
		const noView = credentials(server);
		const err = await runCredentialTest(noView);
		expect(err).toEqual({ status: 'Error', message: expect.stringMatching(/^The service user's role is missing the permission can_view_hosts/) });
		// The sign-in itself succeeded and its token is kept
		expect(noView.sessionToken).toBe(server.issuedTokens.at(-1));

		server.permissions = new Set();
		expect((await runCredentialTest(credentials(server))).message).toMatch(/missing the permission can_view_hosts/);

		// The test marker never reaches PatchMon, and only the test request carries it
		expect(server.requests.some((r) => 'x-n8n-patchmon-credential-test' in r.headers)).toBe(false);
	});

	it('the Integration API test does not need a service user permission check', async () => {
		server.permissions = new Set();
		expect((await runCredentialTest(integrationOnly(server))).status).toBe('OK');
	});

	it('requires both Username and Password for the service user', async () => {
		expect((await runCredentialTest(credentials(server, { password: '' }))).message).toMatch(/Password is required/);
		expect((await runCredentialTest(credentials(server, { username: '' }))).message).toMatch(/Username is required/);
		expect(server.logins).toHaveLength(0);
	});

	it('does not follow a redirect to another host', async () => {
		server.on('GET', '/api/v1/api/hosts', () => ({ status: 302, headers: { Location: `${trap.url}/api/v1/api/hosts` } }));
		expect((await runCredentialTest(integrationOnly(server))).status).toBe('Error');
		server.on('POST', '/api/v1/auth/login', () => ({ status: 307, headers: { Location: `${trap.url}/steal` } }));
		expect((await runCredentialTest(credentials(server))).message).toMatch(/redirect/);
		expect(trap.hits).toHaveLength(0);
	});
});
