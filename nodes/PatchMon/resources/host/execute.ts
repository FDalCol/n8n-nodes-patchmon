import type { IDataObject } from 'n8n-workflow';

import { applyLimit, data, list, type OperationContext, type ResourceHandlers } from '../../shared/engine';
import { getHostPackages, hostPath, listHosts, securityUpdates } from '../../shared/hosts';
import { toList } from '../../shared/security';

async function getOne(ctx: OperationContext, sub: string): Promise<IDataObject> {
	const path = ctx.guard(() => hostPath(ctx.str('hostId'), sub));
	return await ctx.client.integration<IDataObject>(path);
}

export const hostHandlers: ResourceHandlers = {
	getAll: async (ctx) => {
		const filters = ctx.collection('filters');
		const limit = ctx.limit();
		const groups = ctx.guard(() => toList(filters.groups, 100));
		let hosts = await listHosts(ctx.client, groups, true);
		const os = typeof filters.osType === 'string' ? filters.osType.toLowerCase() : '';
		if (filters.status) hosts = hosts.filter((h) => h.effective_status === filters.status);
		if (os) hosts = hosts.filter((h) => String(h.os_type ?? '').toLowerCase().includes(os));
		if (filters.updateState) hosts = hosts.filter((h) => h.update_state === filters.updateState);
		if (filters.reportingState) hosts = hosts.filter((h) => h.reporting_state === filters.reportingState);
		if (typeof filters.needsReboot === 'boolean') hosts = hosts.filter((h) => (h.needs_reboot === true) === filters.needsReboot);
		return list(applyLimit(hosts, limit));
	},

	get: async (ctx) => data(await getOne(ctx, 'info')),
	getNetwork: async (ctx) => data(await getOne(ctx, 'network')),
	getStats: async (ctx) => data(await getOne(ctx, 'stats')),
	getSystem: async (ctx) => data(await getOne(ctx, 'system')),

	getPackages: async (ctx) => {
		const filters = ctx.collection('packageFilters');
		const limit = ctx.limit();
		const hostId = ctx.str('hostId');
		const onlySecurity = filters.onlySecurity === true;
		const answer = await getHostPackages(ctx.client, hostId, onlySecurity || filters.onlyWithUpdates === true);
		if (!answer) throw ctx.client.error('PatchMon API error 404: Host not found', 'Check the Host ID.');
		let packages = onlySecurity ? securityUpdates(answer.packages) : answer.packages;
		const name = typeof filters.name === 'string' ? filters.name.toLowerCase() : '';
		if (name) packages = packages.filter((p) => String(p.name ?? '').toLowerCase().includes(name));
		const host = { id: answer.host.id, hostname: answer.host.hostname, friendly_name: answer.host.friendly_name };
		return list(applyLimit(packages, limit).map((p) => ({ ...p, host })));
	},
};
