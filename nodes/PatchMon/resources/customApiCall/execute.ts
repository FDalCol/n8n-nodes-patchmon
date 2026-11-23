import { jsonParse, type IDataObject } from 'n8n-workflow';

import { data, list, type ResourceHandlers } from '../../shared/engine';
import { assertAccessPath, hasControlChars, isSafeKey, validateApiPath, type AccessType } from '../../shared/security';
import type { PatchMonMethod } from '../../shared/transport';

const PARAM_NAME = /^[A-Za-z0-9_.\-[\]]{1,128}$/;
const METHODS: PatchMonMethod[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const FORBIDDEN_PARAMS = new Set(['token', 'password', 'secret', 'api_key', 'apikey', 'key', 'ticket', 'access_token', 'refresh_token']);

export const customApiCallHandlers: ResourceHandlers = {
	call: async (ctx) => {
		const access = ctx.str('access', 'integration') as AccessType;
		if (access !== 'integration' && access !== 'session') throw ctx.client.error('Access must be Integration API or Service User Session');
		const method = ctx.str('method', 'GET').toUpperCase() as PatchMonMethod;
		if (!METHODS.includes(method)) throw ctx.client.error('Invalid method');
		if (access === 'integration' && method !== 'GET' && method !== 'DELETE') {
			throw ctx.client.error('The Integration API only has GET and DELETE endpoints');
		}
		const path = ctx.guard(() => {
			const p = validateApiPath(ctx.str('path'));
			assertAccessPath(access, p);
			return p;
		});

		const qs: IDataObject = {};
		const raw = ctx.param<{ parameter?: Array<{ name?: string; value?: unknown }> }>('queryParameters', {}) ?? {};
		for (const entry of raw.parameter ?? []) {
			const name = String(entry.name ?? '').trim();
			if (name === '') continue;
			if (!PARAM_NAME.test(name) || !isSafeKey(name)) throw ctx.client.error(`Invalid query parameter name "${name.slice(0, 64)}"`);
			if (FORBIDDEN_PARAMS.has(name.toLowerCase())) throw ctx.client.error(`Query parameter "${name}" is not allowed`);
			const value = entry.value === undefined || entry.value === null ? '' : String(entry.value);
			if (value.length > 2048 || hasControlChars(value)) throw ctx.client.error(`Query parameter "${name}" is too long or contains control characters`);
			qs[name] = value;
		}

		let body: unknown;
		if (method !== 'GET') {
			const rawBody = ctx.param<unknown>('body', '{}');
			if (typeof rawBody === 'string') {
				try {
					body = rawBody.trim() === '' ? undefined : jsonParse(rawBody);
				} catch {
					throw ctx.client.error('Body must be valid JSON');
				}
			} else {
				body = rawBody;
			}
		}

		const res = await ctx.client.request(access, method, path, { qs, body });
		return Array.isArray(res.data) ? list(res.data) : data(res.data);
	},
};
