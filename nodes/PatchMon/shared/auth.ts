/**
 * Basic Auth with the API token goes only to /api/v1/api/*. The service user's access token goes
 * as Bearer only to the other /api/v1 routes of the Base URL it was issued for.
 */
import type { ICredentialDataDecryptedObject, IDataObject, IHttpRequestHelper, IHttpRequestOptions } from 'n8n-workflow';

import { describeNetworkError, errorCode, errorDetail, readBody } from './response';
import {
	API_PREFIX,
	hasControlChars,
	hasTraversal,
	isHeaderSafe,
	isIntegrationPath,
	normalizeBaseUrl,
	redactString,
	stateKey,
} from './security';

export const LOGIN_PATH = '/api/v1/auth/login';
export const PERMISSIONS_PATH = '/api/v1/permissions/user-permissions';
/** Needs a valid session and no permission: used to renew an expired token. */
export const PROFILE_PATH = '/api/v1/auth/profile';

export const NODE_PERMISSIONS = ['can_view_hosts', 'can_manage_patching'];

/** Only on the credential test request; authenticate() removes it before sending. */
export const CREDENTIAL_TEST_HEADER = 'x-n8n-patchmon-credential-test';

/** Every service user operation needs can_view_hosts. */
export function credentialTestProblem(raw: ICredentialDataDecryptedObject): string | undefined {
	if (!hasServiceUser(raw)) return undefined;
	const granted = String(raw.sessionPermissions ?? '').split(',');
	if (granted.includes('can_view_hosts')) return undefined;
	return "The service user's role is missing the permission can_view_hosts, which every service user operation needs. Give it to the role in PatchMon.";
}

const SIGN_IN_TIMEOUT_MS = 30_000;
const SIGN_IN_MAX_BYTES = 1024 * 1024;
const MAX_USERNAME_LENGTH = 255;
const MAX_PASSWORD_LENGTH = 1024;

export const ACCESS_TOKEN_RE = /^[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,1024}$/;

/** Sign-in failure: message and description never contain the password or a token. */
export class PatchMonSignInError extends Error {
	readonly description?: string;

	readonly patchmonSignIn = true;

	/** HTTP status of the sign-in answer. Not named statusCode: NodeApiError would replace the message. */
	signInStatus?: number;

	retryAfterSeconds?: number;

	constructor(message: string, description?: string) {
		super(message);
		this.name = 'PatchMonSignInError';
		this.description = description;
	}
}

export function parseRetryAfter(value: string, now = Date.now()): number | undefined {
	const text = value.trim();
	if (/^\d{1,9}$/.test(text)) return Number(text);
	const date = Date.parse(text);
	return Number.isNaN(date) ? undefined : Math.max(0, Math.ceil((date - now) / 1000));
}

/** n8n wraps the sign-in error in a NodeApiError. */
export function findSignInError(error: unknown): PatchMonSignInError | undefined {
	let current: unknown = error;
	for (let depth = 0; depth < 4 && current && typeof current === 'object'; depth++) {
		if ((current as { patchmonSignIn?: unknown }).patchmonSignIn === true) return current as PatchMonSignInError;
		current = (current as { cause?: unknown }).cause;
	}
	return undefined;
}

function str(raw: ICredentialDataDecryptedObject, key: string, trim = true): string {
	const v = raw[key];
	if (typeof v !== 'string') return '';
	return trim ? v.trim() : v;
}

/** http:// only when the credential explicitly allows it. */
export function credentialBaseUrl(raw: ICredentialDataDecryptedObject): string {
	return normalizeBaseUrl(raw.baseUrl, raw.allowHttp === true);
}

export function serviceUsername(raw: ICredentialDataDecryptedObject): string {
	return str(raw, 'username');
}

function servicePassword(raw: ICredentialDataDecryptedObject): string {
	return str(raw, 'password', false);
}

export function hasServiceUser(raw: ICredentialDataDecryptedObject): boolean {
	return serviceUsername(raw) !== '';
}

export function credentialSecrets(raw: ICredentialDataDecryptedObject): { secrets: string[]; password: string } {
	return { secrets: [str(raw, 'tokenSecret'), str(raw, 'sessionToken')].filter((s) => s !== ''), password: servicePassword(raw) };
}

/** Has no service user and no `sessionToken` field, so n8n never signs in for Integration API requests. */
export function integrationCredentials(raw: ICredentialDataDecryptedObject): ICredentialDataDecryptedObject {
	return { baseUrl: raw.baseUrl, allowHttp: raw.allowHttp, tokenKey: raw.tokenKey, tokenSecret: raw.tokenSecret };
}

export function hasPermission(permissions: IDataObject, permission: string): boolean {
	return permissions[permission] === true;
}

export function basicAuthorization(raw: ICredentialDataDecryptedObject): string {
	const key = str(raw, 'tokenKey');
	const secret = str(raw, 'tokenSecret');
	if (!isHeaderSafe(key, 256) || key.includes(':')) throw new Error('Token Key is missing or contains invalid characters');
	if (!isHeaderSafe(secret, 1024)) throw new Error('Token Secret is missing or contains invalid characters');
	return `Basic ${Buffer.from(`${key}:${secret}`, 'utf8').toString('base64')}`;
}

/** Stable per Base URL and user, so every sign-in reuses one PatchMon session. */
export function deviceId(baseUrl: string, user: string): string {
	return `n8n-${stateKey(`${baseUrl}\n${user}`)}${stateKey(`${user}\n${baseUrl}`)}`;
}

/**
 * The token is part of the input: a fast hash of the password alone could be brute-forced by
 * anyone who sees the stored fingerprint.
 */
export function sessionTokenFingerprint(baseUrl: string, user: string, pass: string, token: string): string {
	const input = `${token}\n${baseUrl}\n${user}\n${pass}`;
	return `v1.${stateKey(input)}.${stateKey(`${input}\n${token}`)}`;
}

/** Only a token issued for this Base URL, username and password. */
export function credentialToken(raw: ICredentialDataDecryptedObject): string {
	const token = str(raw, 'sessionToken');
	if (!ACCESS_TOKEN_RE.test(token) || !hasServiceUser(raw)) return '';
	let baseUrl: string;
	try {
		baseUrl = credentialBaseUrl(raw);
	} catch {
		return '';
	}
	return raw.sessionTokenFingerprint === sessionTokenFingerprint(baseUrl, serviceUsername(raw), servicePassword(raw), token)
		? token
		: '';
}

/** Hashes only, never the password. `session` changes when n8n stores a new token. */
export function signInIdentity(raw: ICredentialDataDecryptedObject): { account: string; session: string } | undefined {
	if (!hasServiceUser(raw)) return undefined;
	let baseUrl: string;
	try {
		baseUrl = credentialBaseUrl(raw);
	} catch {
		baseUrl = String(raw.baseUrl ?? '');
	}
	return {
		account: stateKey(`${baseUrl}\n${serviceUsername(raw)}`),
		session: stateKey(String(raw.sessionTokenFingerprint ?? '')),
	};
}

/** Chosen from the URL, so each secret only reaches the routes of its type on the Base URL. */
export function authorizationFor(raw: ICredentialDataDecryptedObject, options: IHttpRequestOptions): string | undefined {
	let baseUrl: string;
	try {
		baseUrl = credentialBaseUrl(raw);
	} catch {
		return undefined;
	}
	const url = `${options.baseURL ? String(options.baseURL).replace(/\/+$/, '') : ''}${String(options.url ?? '')}`;
	if (!url.startsWith(`${baseUrl}${API_PREFIX}/`)) return undefined;
	const path = url.slice(baseUrl.length).split(/[?#]/)[0];
	if (hasTraversal(path) || /%2f|%5c|\\/i.test(path) || hasControlChars(path)) return undefined;
	if (isIntegrationPath(path)) {
		try {
			return basicAuthorization(raw);
		} catch {
			return undefined;
		}
	}
	const token = credentialToken(raw);
	return token ? `Bearer ${token}` : undefined;
}

interface SignInResponse {
	statusCode: number;
	data: unknown;
	retryAfter: string;
}

/** A clean sign-in error for a failed request, built without any field of the original error. */
function networkFailure(error: unknown, secrets: string[]): PatchMonSignInError {
	const e = error as { code?: string; message?: string; cause?: { code?: string } };
	const raw = `${e?.code ?? ''} ${e?.cause?.code ?? ''} ${e?.message ?? ''}`;
	if (/ERR_RESPONSE_TOO_LARGE|maximum allowed size|maxContentLength/i.test(raw)) {
		return new PatchMonSignInError('Sign-in to PatchMon failed: the response is too large');
	}
	if (/ECONNABORTED|ETIMEDOUT|timeout of \d+ms exceeded/i.test(raw)) {
		return new PatchMonSignInError(`Sign-in to PatchMon timed out after ${SIGN_IN_TIMEOUT_MS / 1000} s`);
	}
	const { message, description } = describeNetworkError(error, false);
	return new PatchMonSignInError(
		redactString(`Sign-in to PatchMon failed: ${message}`, secrets),
		description ? redactString(description, secrets) : undefined,
	);
}

async function call(
	helpers: IHttpRequestHelper['helpers'],
	options: IHttpRequestOptions,
	secrets: string[],
): Promise<SignInResponse> {
	let response: { body?: unknown; statusCode?: number; headers?: IDataObject } | undefined;
	let failure: PatchMonSignInError | undefined;
	try {
		response = (await helpers.httpRequest({
			...options,
			encoding: 'arraybuffer',
			json: false,
			returnFullResponse: true,
			ignoreHttpStatusErrors: true,
			disableFollowRedirect: true,
			sendCredentialsOnCrossOriginRedirect: false,
			timeout: SIGN_IN_TIMEOUT_MS,
			maxResponseBodyBytes: SIGN_IN_MAX_BYTES,
		})) as typeof response;
	} catch (error) {
		// Never rethrow the original error: it holds the request, with the password in its body
		failure = networkFailure(error, secrets);
	}
	if (failure || !response) throw failure ?? new PatchMonSignInError('Sign-in to PatchMon failed: no response');
	const statusCode = Number(response.statusCode ?? 0);
	if (statusCode >= 300 && statusCode < 400) {
		throw new PatchMonSignInError(
			`Sign-in to PatchMon failed: the server answered with a redirect (HTTP ${statusCode}). Redirects are never followed.`,
			'Check that the Base URL points directly to PatchMon (scheme, host, port and path prefix).',
		);
	}
	let data: unknown;
	try {
		const text = readBody(response.body, SIGN_IN_MAX_BYTES);
		data = text.trim() === '' ? undefined : JSON.parse(text);
	} catch {
		data = undefined;
	}
	const headers = response.headers ?? {};
	return { statusCode, data, retryAfter: String(headers['retry-after'] ?? '').slice(0, 32) };
}

function retryAfterOf(res: SignInResponse): number | undefined {
	const header = parseRetryAfter(res.retryAfter);
	if (header !== undefined) return header;
	const remaining = (res.data as IDataObject | undefined)?.remaining_seconds;
	return typeof remaining === 'number' && Number.isFinite(remaining) && remaining >= 0 ? Math.ceil(remaining) : undefined;
}

function signInFailure(res: SignInResponse, secrets: string[]): PatchMonSignInError {
	const detail = redactString(errorDetail(res.data), secrets).slice(0, 500);
	const suffix = detail ? `: ${detail}` : '';
	const wait = retryAfterOf(res);
	let error: PatchMonSignInError;
	switch (res.statusCode) {
		case 400:
			error = new PatchMonSignInError(`PatchMon refused the sign-in request (400)${suffix}`, 'Check Username and Password of the service user.');
			break;
		case 401:
			error = new PatchMonSignInError(
				`PatchMon rejected the service user's username or password (401)${suffix}`,
				'Check Username and Password, and that the user is active and has a local password (SSO-only users cannot sign in here). Repeated failures lock sign-in for this user and address for a while.',
			);
			break;
		case 403:
			error = new PatchMonSignInError(
				`PatchMon refused the sign-in (403)${suffix}`,
				'Local sign-in is turned off (SSO only) or refused for this user. The service user needs a local password and local authentication enabled.',
			);
			break;
		case 404:
			error = new PatchMonSignInError(
				`Sign-in endpoint not found (404)${suffix}`,
				'Check the Base URL (path prefix of a reverse proxy) and that the server runs PatchMon 2.x.',
			);
			break;
		case 429:
			error = new PatchMonSignInError(
				`Too many sign-in attempts, PatchMon locked sign-in for this user (429)${suffix}`,
				wait !== undefined ? `PatchMon asks to wait ${wait} s before trying again.` : 'Wait before trying again.',
			);
			break;
		case 503:
			error = new PatchMonSignInError(`PatchMon is busy and refused the sign-in (503)${suffix}`, 'Try again in a few seconds.');
			break;
		default:
			error = new PatchMonSignInError(`Sign-in to PatchMon failed (HTTP ${res.statusCode})${suffix}`);
	}
	error.signInStatus = res.statusCode;
	if (res.statusCode === 429 || res.statusCode === 503) error.retryAfterSeconds = wait;
	return error;
}

/** Missing permissions never make the sign-in fail; a sign-in PatchMon blocks (MFA enrolment, temporary password) does. */
function readPermissions(res: SignInResponse, secrets: string[]): string[] {
	if (res.statusCode === 403) {
		const code = errorCode(res.data);
		if (code === 'TFA_ENROLMENT_REQUIRED' || code === 'PASSWORD_CHANGE_REQUIRED') {
			throw new PatchMonSignInError(
				code === 'TFA_ENROLMENT_REQUIRED'
					? 'The service user must set up two-factor authentication before it can use PatchMon'
					: 'The service user must replace its temporary password before it can use PatchMon',
				'Sign in once in the PatchMon web UI with this user and complete the required step, or use a user without that requirement.',
			);
		}
		// "No permissions found": the role has no permission at all
		return [];
	}
	if (res.statusCode < 200 || res.statusCode >= 300 || !res.data || typeof res.data !== 'object') {
		throw new PatchMonSignInError(
			redactString(`Could not read the service user's permissions (HTTP ${res.statusCode})`, secrets),
			'Check that the Base URL points to PatchMon 2.x.',
		);
	}
	const perms = res.data as IDataObject;
	return NODE_PERMISSIONS.filter((p) => perms[p] === true);
}

/** Keeps the stored token while PatchMon accepts it, so a credential test does not sign in again. */
export async function preAuthenticate(
	helpers: IHttpRequestHelper['helpers'],
	raw: ICredentialDataDecryptedObject,
): Promise<IDataObject> {
	const user = serviceUsername(raw);
	const pass = servicePassword(raw);
	// Checked first: the credential test runs this step also without a service user
	let baseUrl = '';
	let invalidUrl = '';
	try {
		baseUrl = credentialBaseUrl(raw);
	} catch (error) {
		invalidUrl = (error as Error).message;
	}
	if (invalidUrl) throw new PatchMonSignInError(invalidUrl);
	if (user === '') {
		if (pass !== '') throw new PatchMonSignInError('Username is required when a service user Password is set');
		return {};
	}
	if (pass === '') throw new PatchMonSignInError('Password is required when a service user Username is set');
	if (user.length > MAX_USERNAME_LENGTH || hasControlChars(user)) {
		throw new PatchMonSignInError('Username is too long or contains control characters');
	}
	if (pass.length > MAX_PASSWORD_LENGTH) throw new PatchMonSignInError('Password is too long');

	const saved = credentialToken(raw);
	const secrets = [pass, saved, str(raw, 'tokenSecret')].filter((s) => s !== '');
	const permissions = async (token: string) =>
		await call(
			helpers,
			{ method: 'GET', url: `${baseUrl}${PERMISSIONS_PATH}`, headers: { Accept: 'application/json', Authorization: `Bearer ${token}` } },
			[...secrets, token],
		);

	if (saved !== '') {
		const res = await permissions(saved);
		// Sign in again only when PatchMon no longer accepts the token
		if (res.statusCode !== 401) {
			return {
				sessionToken: saved,
				sessionTokenFingerprint: sessionTokenFingerprint(baseUrl, user, pass, saved),
				sessionPermissions: readPermissions(res, secrets).join(','),
			};
		}
	}

	const res = await call(
		helpers,
		{
			method: 'POST',
			url: `${baseUrl}${LOGIN_PATH}`,
			headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Device-ID': deviceId(baseUrl, user) },
			body: JSON.stringify({ username: user, password: pass }),
		},
		secrets,
	);
	if (res.statusCode < 200 || res.statusCode >= 300) throw signInFailure(res, secrets);
	const answer = (res.data ?? {}) as IDataObject;
	if (answer.requiresTfa === true) {
		throw new PatchMonSignInError(
			'The service user has two-factor authentication (MFA) enabled: n8n cannot sign in with it',
			'Use a dedicated service user without MFA, protected by a long random password and limited to the permissions this node needs.',
		);
	}
	if (answer.tfaEnrolmentRequired === true) {
		throw new PatchMonSignInError(
			'PatchMon requires the service user to set up two-factor authentication first: n8n cannot use it',
			'Use a service user that is not required to enrol in MFA.',
		);
	}
	if (answer.passwordChangeRequired === true) {
		throw new PatchMonSignInError(
			'The service user must replace its temporary password before it can be used',
			'Sign in once in the PatchMon web UI with this user, set a new password and update the credential.',
		);
	}
	const token = typeof answer.token === 'string' ? answer.token : '';
	if (!ACCESS_TOKEN_RE.test(token)) {
		throw new PatchMonSignInError(
			'Sign-in to PatchMon failed: the answer contains no access token',
			'Check that the Base URL points to PatchMon 2.x.',
		);
	}
	const granted = readPermissions(await permissions(token), [...secrets, token]);
	return {
		sessionToken: token,
		sessionTokenFingerprint: sessionTokenFingerprint(baseUrl, user, pass, token),
		sessionPermissions: granted.join(','),
	};
}
