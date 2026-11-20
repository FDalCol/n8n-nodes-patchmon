import { applyLimit, data, list, type ResourceHandlers } from '../../shared/engine';
import { PATCHING_PATH } from '../../shared/patching';
import { validateUuid } from '../../shared/security';

const BASE = `${PATCHING_PATH}/policies`;

export const patchPolicyHandlers: ResourceHandlers = {
	getAll: async (ctx) => {
		const limit = ctx.limit();
		const rows = await ctx.client.session<unknown>('GET', BASE, { permission: 'can_view_hosts' });
		if (!Array.isArray(rows)) throw ctx.client.error('Unexpected answer from PatchMon (expected a list)');
		return list(applyLimit(rows, limit));
	},

	get: async (ctx) => {
		const id = ctx.guard(() => validateUuid(ctx.str('policyId'), 'Policy ID'));
		return data(await ctx.client.session('GET', `${BASE}/${id}`, { permission: 'can_view_hosts' }));
	},
};
