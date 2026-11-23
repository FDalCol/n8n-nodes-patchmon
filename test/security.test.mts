import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { normalizeBaseUrl, redactString, redactValue, validateApiPath } from '../nodes/PatchMon/shared/security';
import { FakePatchMon, HOST_A, PASSWORD, TOKEN_KEY, TOKEN_SECRET, Trap } from './helpers/fakePatchMon.mts';
import { credentials, integrationOnly, runNode, runNodeError, runNodeJson } from './helpers/harness.mts';

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

const call = (extra: Record<string, unknown>) => ({ resource: 'customApiCall', operation: 'call', method: 'GET', access: 'integration', ...extra });

describe('Base URL', () => {
	it('accepts http(s) with an optional prefix and refuses anything else', () => {
		expect(normalizeBaseUrl(' https://pm.example.com/patchmon// ')).toBe('https://pm.example.com/patchmon');
		expect(() => normalizeBaseUrl('http://pm.example.com')).toThrow(/Allow Insecure HTTP/);
		expect(normalizeBaseUrl('http://pm.example.com/', true)).toBe('http://pm.example.com');
		for (const bad of [
			'ftp://pm.example.com',
			'https://user:pass@pm.example.com',
			'https://pm.example.com/?x=1',
			'https://pm.example.com/#x',
			'https://pm.example.com/a/../b',
			'https://pm.example.com/%2e%2e/b',
			'https://pm.example.com/api/v1',
			'javascript:alert(1)',
			'',
		]) {
			expect(() => normalizeBaseUrl(bad), bad).toThrow();
		}
	});
});

describe('Custom API Call', () => {
	it('calls the Integration API with Basic Auth and the session API with the service user', async () => {
		const reports = await runNodeJson({ credentials: credentials(server), params: call({ path: `/api/v1/api/hosts/${HOST_A}/info` }) });
		expect(reports[0]).toMatchObject({ id: HOST_A });
		const runs = await runNodeJson({
			credentials: credentials(server),
			params: call({ access: 'session', path: '/api/v1/patching/runs', queryParameters: { parameter: [{ name: 'limit', value: '5' }] } }),
		});
		expect(runs[0]).toMatchObject({ runs: [], pagination: { limit: 5 } });
		expect(server.requests.filter((r) => r.path.startsWith('/api/v1/api/')).every((r) => String(r.headers.authorization).startsWith('Basic '))).toBe(true);
		expect(server.crossedCredentials).toEqual([]);
	});

	it('a node run with an http:// Base URL fails clearly without sending anything', async () => {
		const err = await runNodeError({ credentials: integrationOnly(server, { allowHttp: false }), params: { resource: 'host', operation: 'getAll', returnAll: true } });
		expect(err.message).toBe('Base URL uses http://. Use https:// or explicitly enable "Allow Insecure HTTP" in the credential');
		expect(server.requests).toHaveLength(0);
	});

	it('refuses absolute URLs, traversal (also encoded) and paths outside the access type', async () => {
		const bad: Array<[Record<string, unknown>, RegExp]> = [
			[{ path: 'https://evil.example/api/v1/api/hosts' }, /Absolute URLs are not allowed/],
			[{ path: '//evil.example/api/v1/api/hosts' }, /Absolute URLs are not allowed/],
			[{ path: '/api/v1/api/../patching/runs' }, /traversal/],
			[{ path: '/api/v1/api/%2e%2e/patching/runs' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/hosts%2f..' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/%68osts' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/hosts?x=1' }, /query string/],
			[{ path: '/api/v1/api/%252e%252e/patching/runs' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/%c0%ae%c0%ae/patching/runs' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/hosts;x=1' }, /forbidden characters/],
			[{ path: '/api/v1/api/..;/patching/runs' }, /forbidden characters/],
			[{ path: '/api/v1/api/hosts%3bx' }, /Encoded path separators or traversal/],
			[{ path: '/api/v1/api/%2e%2e%2fpatching' }, /Encoded path separators or traversal/],
			[{ path: '\\\\evil.example\\api' }, /forbidden characters/],
			[{ access: 'session', path: '/api/v2/patching/runs' }, /Session paths must/],
			[{ access: 'session', path: '/API/v1/patching/runs' }, /Session paths must/],
			[{ path: '/api/v1/patching/runs' }, /Integration API paths must start with \/api\/v1\/api\//],
			[{ path: '/health' }, /Integration API paths must start/],
			[{ access: 'session', path: '/api/v1/api/hosts' }, /Session paths must/],
			[{ access: 'session', path: '/api/v1/auth/login', method: 'POST' }, /Session paths must/],
			[{ access: 'session', path: '/api/v1/auth/logout', method: 'POST' }, /Session paths must/],
			[{ access: 'session', path: '/api/v1/tfa/disable', method: 'POST' }, /Session paths must/],
			[{ access: 'session', path: '/api/v1/gethomepage/stats' }, /Session paths must/],
			[{ access: 'session', path: '/metrics' }, /Session paths must/],
			[{ path: '/api/v1/api/hosts', method: 'POST' }, /only has GET and DELETE/],
			[{ path: '/api/v1/api/hosts', queryParameters: { parameter: [{ name: 'token', value: 'x' }] } }, /not allowed/],
			[{ path: '/api/v1/api/hosts', queryParameters: { parameter: [{ name: '__proto__', value: 'x' }] } }, /Invalid query parameter name/],
		];
		for (const [params, message] of bad) {
			expect((await runNodeError({ credentials: credentials(server), params: call(params) })).message, JSON.stringify(params)).toMatch(message);
		}
		expect(server.requests).toHaveLength(0);
		expect(validateApiPath('api/v1/api/hosts/')).toBe('/api/v1/api/hosts');
	});

	it('does not follow a redirect to another host, with either credential', async () => {
		server.on('GET', '/api/v1/api/hosts', () => ({ status: 302, headers: { Location: `${trap.url}/api/v1/api/hosts` } }));
		server.on('GET', '/api/v1/patching/runs', () => ({ status: 301, headers: { Location: `${trap.url}/collect` } }));
		const a = await runNodeError({ credentials: credentials(server), params: { resource: 'host', operation: 'getAll', returnAll: true } });
		expect(a.message).toMatch(/redirect \(HTTP 302\)\. Redirects are never followed/);
		const b = await runNodeError({ credentials: credentials(server), params: { resource: 'patching', operation: 'getRuns', returnAll: true } });
		expect(b.message).toMatch(/redirect \(HTTP 301\)/);
		expect(trap.hits).toHaveLength(0);
	});

	it('refuses a response above the size limit', async () => {
		server.on('GET', '/api/v1/api/hosts', () => ({ raw: `{"hosts":[],"pad":"${'x'.repeat(70 * 1024 * 1024)}"}` }));
		const err = await runNodeError({ credentials: integrationOnly(server), params: { resource: 'host', operation: 'getAll', returnAll: true } });
		expect(err.message).toMatch(/Response too large/);
	}, 30_000);
});

describe('secrets', () => {
	it('never shows the token secret, password or access token in outputs or errors', async () => {
		const stored = credentials(server);
		await runNodeJson({ credentials: stored, params: { resource: 'patching', operation: 'getRuns', returnAll: true } });
		const token = String(stored.sessionToken);
		server.on('GET', '/api/v1/patching/policies', () => ({
			json: [{ id: 'p1', note: `secret ${TOKEN_SECRET} pw ${PASSWORD} tok ${token}`, token: token, api_key: 'kept' }],
		}));
		server.on('GET', '/api/v1/patching/runs', () => ({ status: 500, json: { error: `boom ${PASSWORD} ${TOKEN_SECRET} Bearer ${token}` } }));
		const out = await runNode({
			credentials: stored,
			continueOnFail: true,
			params: [
				{ resource: 'patchPolicy', operation: 'getAll', returnAll: true },
				{ resource: 'patching', operation: 'getRuns', returnAll: true },
			],
		});
		const text = JSON.stringify(out);
		for (const secret of [TOKEN_SECRET, PASSWORD, token]) expect(text).not.toContain(secret);
		expect(out[0].json.token).toBe('[REDACTED]');
		expect(out[1].json.error).toMatch(/^PatchMon API error 500: boom \[REDACTED\]/);
		const err = await runNodeError({ credentials: stored, params: { resource: 'patching', operation: 'getRuns', returnAll: true } });
		expect(`${err.message} ${err.description ?? ''}`).not.toMatch(new RegExp(`${PASSWORD}|${TOKEN_SECRET}|${token}`));
	});

	it('never puts credentials in a URL and keeps the Integration token away from session routes', async () => {
		const stored = credentials(server);
		await runNodeJson({
			credentials: stored,
			params: [
				{ resource: 'host', operation: 'getAll', returnAll: true },
				{ resource: 'patching', operation: 'getRuns', returnAll: true },
				{ resource: 'patching', operation: 'triggerPatch', hostId: HOST_A, patchType: 'patch_all' },
			],
		});
		for (const r of server.requests) {
			const url = `${r.path}?${r.query.toString()}`;
			for (const secret of [TOKEN_KEY, TOKEN_SECRET, PASSWORD, String(stored.sessionToken)]) expect(url).not.toContain(secret);
		}
		expect(server.crossedCredentials).toEqual([]);
	});

	it('redaction stays linear on hostile text (no ReDoS)', () => {
		const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abcdefghijklmnop';
		for (const hostile of [
			'eyJ'.repeat(1_000_000),
			'password="'.repeat(300_000),
			'Bearer '.repeat(400_000),
			'patchmon_ae_'.repeat(250_000),
			`${'a'.repeat(4000)}.`.repeat(700),
		]) {
			const started = Date.now();
			redactValue({ description: hostile });
			expect(Date.now() - started, hostile.slice(0, 20)).toBeLessThan(1500);
		}
		for (const wrapped of [jwt, `token ${jwt}`, `x=${jwt}`, `(${jwt})`, `"${jwt}"`]) {
			expect(redactString(wrapped)).not.toContain('eyJzdWIi');
		}
	});

	it('redaction patterns', () => {
		expect(redactString('Authorization: Basic abc123==')).toBe('Authorization: [REDACTED]');
		expect(redactString('key patchmon_ae_abcdef123456 used')).toBe('key [REDACTED] used');
		expect(redactString('{"refresh_token":"abc","password":"x"}')).toBe('{"refresh_token":[REDACTED],"password":[REDACTED]}');
		expect(redactValue({ token_secret: 's', tfaTicket: 't', nested: { password: 'p' }, ok: 1 })).toEqual({
			token_secret: '[REDACTED]',
			tfaTicket: '[REDACTED]',
			nested: { password: '[REDACTED]' },
			ok: 1,
		});
	});
});
