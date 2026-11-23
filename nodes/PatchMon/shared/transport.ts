import {
	NodeOperationError,
	sleep,
	type ICredentialDataDecryptedObject,
	type IDataObject,
	type IExecuteFunctions,
	type IHttpRequestMethods,
	type IHttpRequestOptions,
	type ILoadOptionsFunctions,
	type INode,
	type IPollFunctions,
} from 'n8n-workflow';

import {
	credentialSecrets,
	findSignInError,
	hasPermission,
	hasServiceUser,
	integrationCredentials,
	PERMISSIONS_PATH,
	PROFILE_PATH,
} from './auth';
import { describeNetworkError, errorCode, errorDetail, readBody, tooLargeMessage } from './response';
import {
	assertAccessPath,
	MAX_RESPONSE_BYTES,
	normalizeBaseUrl,
	redactString,
	redactValue,
	REQUEST_TIMEOUT_MS,
	type AccessType,
} from './security';

export const CREDENTIAL_NAME = 'patchMonApi';

const MIN_OUTPUT_REDACTION_LENGTH = 8;

export type PatchMonContext = IExecuteFunctions | ILoadOptionsFunctions | IPollFunctions;

export type PatchMonMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface PatchMonRequestOptions {
	qs?: IDataObject;
	body?: unknown;
	timeoutMs?: number;
	maxBytes?: number;
	acceptStatus?: number[];
	/** Permission named in the hint of a 403 ("Insufficient permissions"). */
	permission?: string;
}

export interface SignInFailure {
	message: string;
	description?: string;
	signInStatus?: number;
	retryAfterSeconds?: number;
}

export interface PatchMonResponse<T = unknown> {
	statusCode: number;
	data: T;
}

interface RawResponse {
	statusCode: number;
	statusMessage: string;
	text: string;
}

export class PatchMonClient {
	readonly baseUrl: string;

	private readonly secrets: string[] = [];

	/** Removed from error messages only (a short password would corrupt ordinary output data). */
	private readonly errorSecrets: string[] = [];

	private renewed = false;

	private permissions?: IDataObject;

	/**
	 * A failed sign-in is not stored by n8n, which would sign in again before every request.
	 * Remembering it keeps one attempt per execution, away from PatchMon's sign-in lockout.
	 */
	private signInFailure?: SignInFailure;

	constructor(
		private readonly ctx: PatchMonContext,
		private raw: ICredentialDataDecryptedObject,
	) {
		this.baseUrl = normalizeBaseUrl(raw.baseUrl);
		this.addSecrets(raw);
	}

	static async create(ctx: PatchMonContext): Promise<PatchMonClient> {
		const raw = await ctx.getCredentials(CREDENTIAL_NAME);
		try {
			return new PatchMonClient(ctx, raw);
		} catch (error) {
			throw new NodeOperationError(ctx.getNode(), (error as Error).message);
		}
	}

	private addSecrets(raw: ICredentialDataDecryptedObject): void {
		const { secrets, password } = credentialSecrets(raw);
		for (const s of secrets) if (!this.secrets.includes(s)) this.secrets.push(s);
		if (password && !this.secrets.includes(password) && !this.errorSecrets.includes(password)) {
			(password.length >= MIN_OUTPUT_REDACTION_LENGTH ? this.secrets : this.errorSecrets).push(password);
		}
	}

	get node(): INode {
		return this.ctx.getNode();
	}

	get hasServiceUser(): boolean {
		return hasServiceUser(this.raw);
	}

	/** Used by the trigger to pause sign-ins. */
	get lastSignInFailure(): SignInFailure | undefined {
		return this.signInFailure;
	}

	redact(text: string): string {
		return redactString(text, [...this.secrets, ...this.errorSecrets]);
	}

	redactValue<T>(value: T): T {
		return redactValue(value, this.secrets);
	}

	error(message: string, description?: string): NodeOperationError {
		return new NodeOperationError(this.node, this.redact(message), {
			description: description ? this.redact(description) : undefined,
		});
	}

	private failSignIn(signIn: SignInFailure): NodeOperationError {
		this.signInFailure = {
			message: signIn.message,
			description: signIn.description,
			signInStatus: signIn.signInStatus,
			retryAfterSeconds: signIn.retryAfterSeconds,
		};
		return this.error(signIn.message, signIn.description);
	}

	requireServiceUser(what = 'This operation'): void {
		if (!this.hasServiceUser) {
			throw this.error(
				`${what} needs the service user of the PatchMon credential`,
				'PatchMon offers host groups, repositories, patch policies and patching only through its web UI API. Set Username and Password of a dedicated service user in the credential.',
			);
		}
	}

	/** Read once per execution, so a role changed in PatchMon is seen at the next run. */
	async requirePermission(permission: string, what: string): Promise<void> {
		this.requireServiceUser(what);
		if (!this.permissions) {
			const res = await this.request<IDataObject>('session', 'GET', PERMISSIONS_PATH, { acceptStatus: [403] });
			if (res.statusCode === 403 && errorCode(res.data)) {
				throw this.error(`PatchMon API error 403: ${errorDetail(res.data)}`, this.hint('session', 403, res.data, {}));
			}
			// 403 without a code: "No permissions found" for the role
			this.permissions = res.statusCode === 403 || !res.data || typeof res.data !== 'object' ? {} : res.data;
		}
		if (!hasPermission(this.permissions, permission)) {
			throw this.error(
				`${what} needs the permission ${permission}, which the service user's role does not have: nothing was changed in PatchMon`,
				`Give ${permission} to the role of the service user in PatchMon, or use a service user whose role has it.`,
			);
		}
	}

	async integration<T = unknown>(path: string, qs?: IDataObject): Promise<T> {
		return (await this.request<T>('integration', 'GET', path, { qs })).data;
	}

	async session<T = unknown>(method: PatchMonMethod, path: string, opts: PatchMonRequestOptions = {}): Promise<T> {
		return (await this.request<T>('session', method, path, opts)).data;
	}

	async request<T = unknown>(
		access: AccessType,
		method: PatchMonMethod,
		path: string,
		opts: PatchMonRequestOptions = {},
	): Promise<PatchMonResponse<T>> {
		try {
			assertAccessPath(access, path);
		} catch (error) {
			throw this.error((error as Error).message);
		}
		this.throwIfCancelled();
		if (access === 'session') {
			this.requireServiceUser();
			if (this.signInFailure) throw this.error(this.signInFailure.message, this.signInFailure.description);
		}
		let res = await this.send(access, method, path, opts);
		if (res.statusCode === 401 && access === 'session' && !this.renewed) {
			// PatchMon refused the stored token (expired, revoked or inactive session): sign in
			// again once, then repeat the request. A 401 is answered before any handler runs.
			this.renewed = true;
			await this.renewSession();
			res = await this.send(access, method, path, opts);
		}
		return this.handleResponse<T>(access, res, opts);
	}

	/**
	 * n8n signs in again (preAuthentication) only when a request made through
	 * httpRequestWithAuthentication fails with 401. The node's own requests read every status
	 * code, so this cheap request (which throws on 401) triggers it; n8n then stores the token.
	 */
	private async renewSession(): Promise<void> {
		try {
			await this.ctx.helpers.httpRequestWithAuthentication.call(this.ctx, CREDENTIAL_NAME, {
				method: 'GET',
				url: `${this.baseUrl}${PROFILE_PATH}`,
				headers: { Accept: 'application/json' },
				encoding: 'arraybuffer',
				json: false,
				returnFullResponse: true,
				disableFollowRedirect: true,
				sendCredentialsOnCrossOriginRedirect: false,
				timeout: REQUEST_TIMEOUT_MS,
				maxResponseBodyBytes: 1024 * 1024,
			});
		} catch (error) {
			const signIn = findSignInError(error);
			if (signIn) throw this.failSignIn(signIn);
			if (this.isCancelled()) throw this.error('Execution was cancelled');
			const status = (error as { httpCode?: unknown }).httpCode;
			if (String(status) === '401') {
				throw this.error(
					'PatchMon API error 401: the server still refuses the session after signing in again',
					'Check that the Base URL points directly to PatchMon and that no proxy in front of it asks for its own authentication.',
				);
			}
			const { message, description } = describeNetworkError(error, false);
			throw this.error(`Sign-in to PatchMon failed: ${message}`, description);
		}
		const renewed = await this.ctx.getCredentials(CREDENTIAL_NAME);
		this.addSecrets(renewed);
		this.raw = renewed;
	}

	private async send(access: AccessType, method: PatchMonMethod, path: string, opts: PatchMonRequestOptions): Promise<RawResponse> {
		const timeoutMs = opts.timeoutMs ?? REQUEST_TIMEOUT_MS;
		const maxBytes = opts.maxBytes ?? MAX_RESPONSE_BYTES;
		const headers: IDataObject = { Accept: 'application/json' };
		// The response is buffered by n8n. `timeout` closes an idle connection and
		// `maxResponseBodyBytes` closes it as soon as the body exceeds the limit: no timer of ours.
		const options: IHttpRequestOptions = {
			method: method as IHttpRequestMethods,
			url: `${this.baseUrl}${path}`,
			headers,
			encoding: 'arraybuffer',
			maxResponseBodyBytes: maxBytes,
			json: false,
			returnFullResponse: true,
			ignoreHttpStatusErrors: true,
			disableFollowRedirect: true,
			sendCredentialsOnCrossOriginRedirect: false,
			timeout: timeoutMs,
			arrayFormat: 'repeat',
		};
		if (opts.qs) {
			const qs: IDataObject = {};
			for (const [k, v] of Object.entries(opts.qs)) {
				if (v === undefined || v === null || v === '') continue;
				qs[k] = typeof v === 'boolean' ? (v ? 'true' : 'false') : (v as string);
			}
			if (Object.keys(qs).length) options.qs = qs;
		}
		if (method !== 'GET' && opts.body !== undefined) {
			headers['Content-Type'] = 'application/json';
			options.body = JSON.stringify(opts.body);
		}

		let response: { body?: unknown; statusCode?: number; statusMessage?: string };
		try {
			response = (await this.ctx.helpers.httpRequestWithAuthentication.call(
				this.ctx,
				CREDENTIAL_NAME,
				options,
				// Integration API: a credential without the service user, so n8n never signs in for it
				access === 'integration'
					? { credentialsDecrypted: { id: '', name: '', type: CREDENTIAL_NAME, data: integrationCredentials(this.raw) } }
					: undefined,
			)) as typeof response;
		} catch (error) {
			const signIn = findSignInError(error);
			if (signIn) throw this.failSignIn(signIn);
			const e = error as { code?: string; message?: string; cause?: { code?: string; message?: string } };
			const detail = `${e?.code ?? ''} ${e?.cause?.code ?? ''} ${e?.message ?? ''} ${e?.cause?.message ?? ''}`;
			if (/ERR_RESPONSE_TOO_LARGE|maximum allowed size|maxContentLength/i.test(detail)) throw this.error(tooLargeMessage(maxBytes));
			if (this.isCancelled()) throw this.error('Execution was cancelled');
			if (/ECONNABORTED|ETIMEDOUT|timeout of \d+ms exceeded/i.test(detail)) {
				throw this.error(`Request to PatchMon timed out after ${Math.round(timeoutMs / 1000)} s`);
			}
			const { message, description } = describeNetworkError(error);
			throw this.error(message, description);
		}
		const statusCode = Number(response?.statusCode ?? 0);
		if (statusCode >= 300 && statusCode < 400) {
			throw this.error(
				`The server answered with a redirect (HTTP ${statusCode}). Redirects are never followed.`,
				'Check that the Base URL points directly to PatchMon (scheme, host, port and path prefix).',
			);
		}
		let text: string;
		try {
			text = readBody(response?.body, maxBytes);
		} catch {
			throw this.error(tooLargeMessage(maxBytes));
		}
		return { statusCode, statusMessage: String(response?.statusMessage ?? ''), text };
	}

	isCancelled(): boolean {
		const getSignal = (this.ctx as { getExecutionCancelSignal?: () => AbortSignal | undefined }).getExecutionCancelSignal;
		return typeof getSignal === 'function' && getSignal.call(this.ctx)?.aborted === true;
	}

	throwIfCancelled(): void {
		if (this.isCancelled()) throw this.error('Execution was cancelled');
	}

	/** Waits in one-second slices, so a cancelled execution stops within a second. */
	async pause(ms: number): Promise<void> {
		this.throwIfCancelled();
		let left = ms;
		while (left > 0) {
			const step = Math.min(left, 1000);
			await sleep(step);
			left -= step;
			this.throwIfCancelled();
		}
	}

	private hint(access: AccessType, statusCode: number, body: unknown, opts: PatchMonRequestOptions): string | undefined {
		const code = errorCode(body);
		if (statusCode === 401) {
			return access === 'integration'
				? 'The Integration API refused the Token Key or Token Secret: the token is wrong, disabled, expired or not of type API.'
				: 'PatchMon refused the session of the service user even after signing in again.';
		}
		if (statusCode === 403) {
			if (code === 'TFA_ENROLMENT_REQUIRED') return 'The service user must set up two-factor authentication in the web UI first; use a service user without that requirement.';
			if (code === 'PASSWORD_CHANGE_REQUIRED') return 'The service user must replace its temporary password in the web UI first.';
			if (code === 'module_not_available') return 'This feature is not included in the PatchMon plan of this server.';
			if (access === 'integration') return 'The Integration API token needs the scope host: get, and its allowed IP ranges must include n8n.';
			return opts.permission
				? `The service user's role needs the permission ${opts.permission}.`
				: "The service user's role lacks the permission this endpoint requires.";
		}
		if (statusCode === 404) return 'Check the ID and that the Base URL points to PatchMon 2.x.';
		if (statusCode === 409) return 'PatchMon refused the request in the current state (for example another patch run is active on the host).';
		if (statusCode === 429) return 'Too many requests: wait and try again.';
		return undefined;
	}

	private handleResponse<T>(access: AccessType, res: RawResponse, opts: PatchMonRequestOptions): PatchMonResponse<T> {
		let parsed: unknown;
		if (res.text.trim() !== '') {
			try {
				parsed = JSON.parse(res.text);
			} catch {
				parsed = undefined;
			}
		}
		const ok = res.statusCode >= 200 && res.statusCode < 300;
		if (!ok && !(opts.acceptStatus ?? []).includes(res.statusCode)) {
			const detail = errorDetail(parsed) || res.statusMessage.trim() || 'Request failed';
			throw this.error(`PatchMon API error ${res.statusCode}: ${detail}`, this.hint(access, res.statusCode, parsed, opts));
		}
		if (ok && parsed === undefined && res.text.trim() !== '') {
			throw this.error(
				'Invalid response from the server (not a PatchMon JSON response)',
				'Check that the Base URL points to PatchMon and not to another web page.',
			);
		}
		return { statusCode: res.statusCode, data: (parsed ?? null) as T };
	}

	guard<T>(fn: () => T): T {
		try {
			return fn();
		} catch (error) {
			throw this.error((error as Error).message);
		}
	}

	guardList(values: string[], validate: (value: string) => string): string[] {
		return this.guard(() => values.map(validate));
	}
}
