/**
 * Requests go through the real n8n 2.45 HTTP code (@n8n/backend-network 1.19.0), after
 * preAuthentication and authenticate() as n8n 2.45 runs them. The `credentials` object of a run
 * is the stored credential: preAuthentication results are saved into it.
 */
import { createRequire } from 'node:module';
import { join } from 'node:path';

import {
	NodeApiError,
	type IAdditionalCredentialOptions,
	type ICredentialDataDecryptedObject,
	type IDataObject,
	type IHttpRequestOptions,
	type INode,
	type INodeExecutionData,
	type JsonObject,
} from 'n8n-workflow';

import { PatchMonApi } from '../../credentials/PatchMonApi.credentials';
import { PatchMon } from '../../nodes/PatchMon/PatchMon.node';
import { PatchMonTrigger } from '../../nodes/PatchMonTrigger/PatchMonTrigger.node';
import { PASSWORD, TOKEN_KEY, TOKEN_SECRET, USERNAME } from './fakePatchMon.mts';

const requireCjs = createRequire(import.meta.url);
const { httpRequest } = requireCjs(
	join(process.cwd(), 'node_modules', '@n8n', 'backend-network', 'dist', 'http', 'axios', 'request.js'),
) as { httpRequest: (o: IHttpRequestOptions) => Promise<unknown> };

export type Params = Record<string, unknown>;

/** Integration API token and service user, as stored by n8n (no session token yet). */
export function credentials(server: { url: string }, extra: IDataObject = {}): ICredentialDataDecryptedObject {
	return { baseUrl: server.url, tokenKey: TOKEN_KEY, tokenSecret: TOKEN_SECRET, username: USERNAME, password: PASSWORD, ...extra };
}

/** Integration API token only. */
export function integrationOnly(server: { url: string }, extra: IDataObject = {}): ICredentialDataDecryptedObject {
	return { baseUrl: server.url, tokenKey: TOKEN_KEY, tokenSecret: TOKEN_SECRET, ...extra };
}

export const credentialType = new PatchMonApi();

export const sentRequests: IHttpRequestOptions[] = [];

/** Number of times n8n stored data returned by preAuthentication in the credential. */
export const credentialSaves = { count: 0 };

/** Credential data as n8n reads it from the database: a fresh copy with defaults applied. */
export function readCredentials(stored: ICredentialDataDecryptedObject): ICredentialDataDecryptedObject {
	const out: ICredentialDataDecryptedObject = {};
	for (const prop of credentialType.properties) {
		if (prop.type !== 'notice') out[prop.name] = prop.default as string;
	}
	return { ...out, ...stored };
}

/** The real outbound request of n8n 2.45 (redirect, timeout and size limits included). */
async function outbound(options: IHttpRequestOptions): Promise<unknown> {
	sentRequests.push(options);
	return await httpRequest(options);
}

/**
 * credentialsHelper.preAuthentication of n8n 2.45 (packages/cli credentials-helper.ts): runs the
 * credential's preAuthentication when the expirable hidden field is empty, after a 401
 * (expired) or for a credential test, and stores the result in the credential.
 */
async function preAuthentication(
	stored: ICredentialDataDecryptedObject,
	creds: ICredentialDataDecryptedObject,
	node: INode,
	expired: boolean,
): Promise<ICredentialDataDecryptedObject | undefined> {
	const expirable = credentialType.properties.find((p) => p.type === 'hidden' && p.typeOptions?.expirable === true);
	if (expirable?.name === undefined) return undefined;
	const isTestingCredentials = node.parameters?.temp === '' && node.type === 'n8n-nodes-base.noOp';
	if (creds[expirable.name] === '' || expired || isTestingCredentials) {
		const output = await credentialType.preAuthentication!.call({ helpers: { httpRequest: outbound } } as never, creds);
		if (output[expirable.name] === undefined) return undefined;
		if (node.credentials) {
			Object.assign(stored, output);
			credentialSaves.count++;
			return Object.assign(creds, output);
		}
	}
	return undefined;
}

/**
 * httpRequestWithAuthentication of n8n-core 2.45: preAuthentication, authenticate(), the request,
 * and once more preAuthentication(expired) + retry when the request throws with status 401.
 * Errors are wrapped in NodeApiError. `credentialsDecrypted` replaces the stored credential.
 */
export async function httpRequestWithAuthentication(
	node: INode,
	stored: ICredentialDataDecryptedObject,
	options: IHttpRequestOptions,
	credentialsDecrypted?: ICredentialDataDecryptedObject,
): Promise<unknown> {
	const authenticate = credentialType.authenticate as (c: ICredentialDataDecryptedObject, o: IHttpRequestOptions) => Promise<IHttpRequestOptions>;
	let creds: ICredentialDataDecryptedObject | undefined;
	try {
		creds = credentialsDecrypted ?? readCredentials(stored);
		const data = await preAuthentication(stored, creds, node, false);
		if (data) Object.assign(creds, data);
		return await outbound(await authenticate(creds, { ...options }));
	} catch (error) {
		if (creds !== undefined && (error as { response?: { status?: number } }).response?.status === 401) {
			try {
				const data = await preAuthentication(stored, creds, node, true);
				if (data) Object.assign(creds, data);
				return await outbound(await authenticate(creds, { ...options }));
			} catch (retryError) {
				throw new NodeApiError(node, retryError as JsonObject);
			}
		}
		throw new NodeApiError(node, error as JsonObject);
	}
}

/** Node used by n8n's credential test (CredentialsTester.runRequestTest, after Workflow defaults). */
const TEST_NODE: INode = {
	id: 'temp',
	name: 'Temp-Node',
	type: 'n8n-nodes-base.noOp',
	typeVersion: 1,
	position: [0, 0],
	parameters: { temp: '' },
	credentials: { patchMonApi: { id: '1', name: 'PatchMon' } },
};

/**
 * The Test button of n8n 2.45: the declarative test request through httpRequestWithAuthentication
 * with the form data (default: the stored data), then the responseCode rules, else the message.
 */
export async function runCredentialTest(
	stored: ICredentialDataDecryptedObject,
	form: ICredentialDataDecryptedObject = readCredentials(stored),
): Promise<{ status: 'OK' | 'Error'; message: string }> {
	const req = credentialType.test.request;
	const options: IHttpRequestOptions = {
		baseURL: String(evalCredentialExpression(req.baseURL, form)),
		url: String(req.url),
		method: req.method,
		headers: req.headers as Record<string, string>,
		disableFollowRedirect: req.disableFollowRedirect,
		maxResponseBodyBytes: req.maxResponseBodyBytes,
		timeout: 5000,
	};
	try {
		await httpRequestWithAuthentication(TEST_NODE, stored, options, { ...form });
	} catch (error) {
		const e = error as Error & { cause?: { response?: { status: number; statusText?: string }; code?: string; message?: string } };
		if (e.cause?.response) {
			const status = e.cause.response.status;
			const rule = credentialType.test.rules?.find((r) => r.type === 'responseCode' && (r.properties as { value: number }).value === status);
			if (rule) return { status: 'Error', message: (rule.properties as { message: string }).message };
			return { status: 'Error', message: e.cause.response.statusText || `Received HTTP status code: ${status}` };
		}
		// Like CredentialsTester 2.45: the error code of the cause, else the message of the error
		if (e.cause?.code) return { status: 'Error', message: e.cause.code };
		return { status: 'Error', message: String(e.message) };
	}
	return { status: 'OK', message: 'Connection successful!' };
}

export { httpRequest };

function getParam(params: Params, name: string, fallback: unknown): unknown {
	return name in params ? params[name] : fallback;
}

export const NODE: INode = {
	id: 'node-1',
	name: 'PatchMon',
	type: 'n8n-nodes-patchmon.patchMon',
	typeVersion: 1,
	position: [0, 0],
	parameters: {},
	credentials: { patchMonApi: { id: '1', name: 'PatchMon' } },
};

export interface RunOptions {
	credentials: ICredentialDataDecryptedObject;
	params: Params | Params[];
	items?: INodeExecutionData[];
	continueOnFail?: boolean;
	cancelSignal?: AbortSignal;
}

function helpers(stored: ICredentialDataDecryptedObject, cancelSignal?: AbortSignal) {
	return {
		httpRequestWithAuthentication: async function (_type: string, o: IHttpRequestOptions, extra?: IAdditionalCredentialOptions) {
			// Like n8n-core 2.45: a node-supplied abortSignal is replaced by the execution cancel signal
			return await httpRequestWithAuthentication(NODE, stored, { ...o, abortSignal: cancelSignal }, extra?.credentialsDecrypted?.data);
		},
	};
}

export async function runNode(opts: RunOptions): Promise<INodeExecutionData[]> {
	const items = opts.items ?? (Array.isArray(opts.params) ? opts.params.map(() => ({ json: {} })) : [{ json: {} }]);
	const paramsFor = (i: number): Params => (Array.isArray(opts.params) ? (opts.params[i] ?? {}) : opts.params);
	const ctx = {
		getInputData: () => items,
		getNode: () => NODE,
		getCredentials: async () => readCredentials(opts.credentials),
		continueOnFail: () => opts.continueOnFail === true,
		getExecutionCancelSignal: () => opts.cancelSignal,
		getNodeParameter: (name: string, i: number, fallback?: unknown) => getParam(paramsFor(i), name, fallback),
		helpers: helpers(opts.credentials, opts.cancelSignal),
	};
	const result = await new PatchMon().execute.call(ctx as never);
	return result[0];
}

export async function runNodeJson(opts: RunOptions): Promise<IDataObject[]> {
	return (await runNode(opts)).map((i) => i.json);
}

export async function runNodeError(opts: RunOptions): Promise<Error & { description?: string }> {
	return await runNode(opts).then(
		() => {
			throw new Error('expected an error');
		},
		(e: Error & { description?: string }) => e,
	);
}

export interface PollOptions {
	credentials: ICredentialDataDecryptedObject;
	params: Params;
	mode?: 'manual' | 'trigger';
	staticData: IDataObject;
}

export async function poll(opts: PollOptions): Promise<IDataObject[] | null> {
	const ctx = {
		getNode: () => ({ ...NODE, name: 'PatchMon Trigger', type: 'n8n-nodes-patchmon.patchMonTrigger' }),
		getMode: () => opts.mode ?? 'trigger',
		getCredentials: async () => readCredentials(opts.credentials),
		getWorkflowStaticData: () => opts.staticData,
		getNodeParameter: (name: string, fallback?: unknown) => getParam(opts.params, name, fallback),
		helpers: helpers(opts.credentials),
	};
	const result = await new PatchMonTrigger().poll.call(ctx as never);
	return result ? result[0].map((i) => i.json) : null;
}

/** Evaluates an n8n "={{ ... }}" expression of the credential test with $credentials. */
export function evalCredentialExpression(expr: unknown, creds: ICredentialDataDecryptedObject): unknown {
	if (typeof expr !== 'string' || !expr.startsWith('={{')) return expr;
	const code = expr.slice(3, -2);
	// eslint-disable-next-line @typescript-eslint/no-implied-eval
	return new Function('$credentials', `return (${code});`)(creds);
}
