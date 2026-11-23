import type { IDataObject } from 'n8n-workflow';

import { applyLimit, data, list, type ResourceHandlers } from '../../shared/engine';
import { MAX_LIST_ENTRIES, MAX_POLL_ITERATIONS, validateId, validateText, validateUuid } from '../../shared/security';

const BASE = '/api/v1/repositories';
/** PatchMon caps a page at 500. */
const PAGE_SIZE = 500;

export const repositoryHandlers: ResourceHandlers = {
	getAll: async (ctx) => {
		const filters = ctx.collection('filters');
		const limit = ctx.limit() ?? MAX_LIST_ENTRIES;
		const qs: IDataObject = ctx.guard(() => ({
			host: filters.host ? validateUuid(filters.host, 'Host ID') : undefined,
			search: filters.search ? validateText(filters.search, 'Search', 200) : undefined,
			status: filters.status === 'active' || filters.status === 'inactive' ? filters.status : undefined,
			type: filters.type === 'secure' || filters.type === 'insecure' ? filters.type : undefined,
		}));
		const rows: unknown[] = [];
		for (let page = 0; page < MAX_POLL_ITERATIONS && rows.length < limit; page++) {
			const size = Math.min(PAGE_SIZE, limit - rows.length);
			const answer = await ctx.client.session<IDataObject>('GET', BASE, {
				qs: { ...qs, limit: size, offset: rows.length, sort: 'name', order: 'asc' },
				permission: 'can_view_hosts',
			});
			if (!answer || !Array.isArray(answer.items)) throw ctx.client.error('Unexpected answer from PatchMon for the repository list');
			const items = answer.items as unknown[];
			rows.push(...items);
			const total = Number(answer.total ?? 0);
			// A page can be shorter than requested: rely on total
			if (items.length === 0 || rows.length >= total) break;
		}
		return list(applyLimit(rows, limit));
	},

	get: async (ctx) => {
		const id = ctx.guard(() => validateId(ctx.str('repositoryId'), 'Repository ID'));
		return data(await ctx.client.session('GET', `${BASE}/${id}`, { permission: 'can_view_hosts' }));
	},

	getByHost: async (ctx) => {
		const limit = ctx.limit();
		const hostId = ctx.guard(() => validateUuid(ctx.str('hostId'), 'Host ID'));
		const rows = await ctx.client.session<unknown>('GET', `${BASE}/host/${hostId}`, { permission: 'can_view_hosts' });
		if (!Array.isArray(rows)) throw ctx.client.error('Unexpected answer from PatchMon (expected a list)');
		return list(applyLimit(rows, limit));
	},
};
