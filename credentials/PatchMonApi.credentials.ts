import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IDataObject,
	IHttpRequestHelper,
	IHttpRequestOptions,
	Icon,
	INodeProperties,
} from 'n8n-workflow';

import { authorizationFor, CREDENTIAL_TEST_HEADER, credentialTestProblem, preAuthenticate } from '../nodes/PatchMon/shared/auth';

/** n8n 2.45 runs preAuthentication when `sessionToken` is empty, after a 401 and on every credential test. */
export class PatchMonApi implements ICredentialType {
	name = 'patchMonApi';

	displayName = 'PatchMon API';

	icon: Icon = { light: 'file:../icons/patchmon.svg', dark: 'file:../icons/patchmon.dark.svg' };

	documentationUrl = 'https://github.com/FDalCol/n8n-nodes-patchmon#credentials';

	properties: INodeProperties[] = [
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'https://patchmon.example.com',
			description:
				'Address of the PatchMon server (http:// or https://, optional path prefix of a reverse proxy), without /api/v1. Must not contain credentials, query or fragment.',
		},
		{
			displayName: 'Token Key',
			name: 'tokenKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			placeholder: 'patchmon_ae_…',
			description:
				'Key of an Integration API token (Settings > Integrations > New Token > API) with the scope host: get. Sent as Basic Auth only to /api/v1/api/*.',
		},
		{
			displayName: 'Token Secret',
			name: 'tokenSecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description: 'Secret of the Integration API token, shown by PatchMon only once',
		},
		{
			displayName:
				'Service user (optional): needed only for host groups, repositories, patch policies and patching. Use a dedicated local user without MFA whose role has can_view_hosts, plus can_manage_patching only if n8n should start, approve or cancel patch runs.',
			name: 'serviceUserNotice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Username',
			name: 'username',
			type: 'string',
			default: '',
			description: 'Username or email of the PatchMon service user. Leave empty to use only the Integration API.',
		},
		{
			displayName: 'Password',
			name: 'password',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'Password of the service user. n8n signs in only when it has no valid access token or PatchMon refuses it (401), and reuses one PatchMon session.',
		},
		{
			displayName: 'Session Token',
			name: 'sessionToken',
			type: 'hidden',
			// expirable: n8n runs preAuthentication when it is empty and after a 401.
			// password: n8n never sends the stored value to the browser.
			typeOptions: { expirable: true, password: true },
			default: '',
		},
		{
			displayName: 'Session Token Fingerprint',
			name: 'sessionTokenFingerprint',
			type: 'hidden',
			// Derived from the password and the token: never sent to the browser either.
			typeOptions: { password: true },
			default: '',
		},
		{
			displayName: 'Session Permissions',
			name: 'sessionPermissions',
			type: 'hidden',
			// Read at sign-in, checked by the credential test
			default: '',
		},
	];

	async preAuthentication(this: IHttpRequestHelper, credentials: ICredentialDataDecryptedObject): Promise<IDataObject> {
		return await preAuthenticate(this.helpers, credentials);
	}

	authenticate = async (
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> => {
		const headers: IDataObject = { ...(requestOptions.headers ?? {}) };
		// Only the credential test request carries this header; it never reaches PatchMon
		const markers = Object.keys(headers).filter((k) => k.toLowerCase() === CREDENTIAL_TEST_HEADER);
		for (const key of markers) delete headers[key];
		if (markers.length) {
			const problem = credentialTestProblem(credentials);
			if (problem) throw new Error(problem);
		}
		const authorization = authorizationFor(credentials, requestOptions);
		if (!authorization && !markers.length) return requestOptions;
		if (authorization) headers.Authorization = authorization;
		return { ...requestOptions, headers };
	};

	/** preAuthentication runs first: the test fails if the service user lacks can_view_hosts. */
	test: ICredentialTestRequest = {
		request: {
			// http(s) only, without credentials, query or fragment. Anything else resolves to an
			// unreachable .invalid host, so the test fails without contacting any server.
			baseURL:
				'={{ /^https?:\\/\\/[^\\/@?#]+(\\/[^?#@]*)?$/i.test(String($credentials.baseUrl || "").trim()) ? String($credentials.baseUrl).trim().replace(/\\/+$/, "") : "https://base-url-must-be-http-or-https-without-credentials-query-or-fragment.invalid" }}',
			url: '/api/v1/api/hosts',
			method: 'GET',
			headers: {
				Accept: 'application/json',
				'X-N8n-PatchMon-Credential-Test': '1',
			},
			disableFollowRedirect: true,
			timeout: 30_000,
			maxResponseBodyBytes: 16 * 1024 * 1024,
		},
		rules: [
			{
				type: 'responseCode',
				properties: {
					value: 401,
					message:
						'Integration API authentication failed (401): the Token Key or Token Secret is wrong, or the token is disabled, expired or not of type API',
				},
			},
			{
				type: 'responseCode',
				properties: {
					value: 403,
					message:
						'Integration API access denied (403): the token needs the scope host: get, or its allowed IP ranges do not include n8n',
				},
			},
			{
				type: 'responseCode',
				properties: {
					value: 404,
					message: 'Integration API not found (404): check the Base URL (without /api/v1) and that the server runs PatchMon 2.x',
				},
			},
		],
	};
}
