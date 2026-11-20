import { applyLimit, data, list, type OperationContext, type ResourceHandlers } from '../../shared/engine';
import { validateId } from '../../shared/security';

const BASE = '/api/v1/host-groups';

function groupPath(ctx: OperationContext, sub = ''): string {
	return `${BASE}/${ctx.guard(() => validateId(ctx.str('groupId'), 'Host Group ID'))}${sub}`;
}

async function getList(ctx: OperationContext, path: string) {
	const limit = ctx.limit();
	const rows = await ctx.client.session<unknown>('GET', path, { permission: 'can_view_hosts' });
	if (!Array.isArray(rows)) throw ctx.client.error('Unexpected answer from PatchMon (expected a list)');
	return list(applyLimit(rows, limit));
}

export const hostGroupHandlers: ResourceHandlers = {
	getAll: async (ctx) => await getList(ctx, BASE),
	get: async (ctx) => data(await ctx.client.session('GET', groupPath(ctx), { permission: 'can_view_hosts' })),
	getHosts: async (ctx) => await getList(ctx, groupPath(ctx, '/hosts')),
};
