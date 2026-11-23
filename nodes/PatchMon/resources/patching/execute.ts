import type { IDataObject } from 'n8n-workflow';

import { applyLimit, data, items, list, type OperationContext, type OperationResult, type ResourceHandlers } from '../../shared/engine';
import {
	BLOCKING_STATUSES,
	PATCHING_PATH,
	blockingRunsByHost,
	getActiveRuns,
	getRun,
	runPath,
	runSummary,
	triggerRun,
	waitForRun,
	type TriggerBody,
} from '../../shared/patching';
import {
	MAX_LIST_ENTRIES,
	MAX_PACKAGES_PER_RUN,
	MAX_POLL_INTERVAL_SECONDS,
	MAX_POLL_ITERATIONS,
	MAX_WAIT_SECONDS,
	MIN_POLL_INTERVAL_SECONDS,
	toList,
	validateInteger,
	validatePackageName,
	validateUuid,
} from '../../shared/security';
import { patchSecurityUpdates } from './securityUpdates';

/** PatchMon caps a page of runs at 200. */
const RUNS_PAGE_SIZE = 200;

const RUN_STATUS_VALUES = new Set([
	'active',
	'agent_disconnected',
	'approved',
	'cancelled',
	'completed',
	'failed',
	'pending_approval',
	'pending_validation',
	'queued',
	'running',
	'scheduled',
	'timed_out',
	'validated',
]);

function withoutOutput(run: IDataObject, include: boolean): IDataObject {
	if (include) return run;
	const rest = { ...run };
	delete rest.shell_output;
	return rest;
}

interface WaitSettings {
	maxWaitMs: number;
	intervalMs: number;
}

/** Validated before anything starts, also values from expressions. */
function waitSettings(ctx: OperationContext): WaitSettings | undefined {
	if (!ctx.bool('waitForCompletion')) return undefined;
	return ctx.guard(() => ({
		maxWaitMs: validateInteger(ctx.param('maxWaitMinutes', 30), 'Max Wait (Minutes)', 1, MAX_WAIT_SECONDS / 60) * 60_000,
		intervalMs:
			validateInteger(ctx.param('pollIntervalSeconds', 15), 'Poll Interval (Seconds)', MIN_POLL_INTERVAL_SECONDS, MAX_POLL_INTERVAL_SECONDS) *
			1000,
	}));
}

/** A run that its patch policy schedules after Max Wait is returned at once. */
async function maybeWait(ctx: OperationContext, result: IDataObject, wait: WaitSettings | undefined): Promise<IDataObject> {
	if (!wait || typeof result.patch_run_id !== 'string') return result;
	const startsAt = Date.parse(String(result.run_at ?? ''));
	const startsIn = Number.isNaN(startsAt) ? 0 : startsAt - Date.now();
	if (startsIn > wait.maxWaitMs) {
		return {
			...result,
			waited: false,
			wait_note: `The run starts at ${String(result.run_at)} (patch policy), after Max Wait: not waited. Use the PatchMon Trigger (Patch Run Finished) to follow it.`,
		};
	}
	const { run, finished } = await waitForRun(ctx.client, result.patch_run_id, wait.maxWaitMs, wait.intervalMs);
	return { ...result, waited: true, finished, status: run.status, run: withoutOutput(run, ctx.bool('includeOutput', true)) };
}

async function triggerPatch(ctx: OperationContext): Promise<OperationResult> {
	const client = ctx.client;
	client.requireServiceUser('Trigger Patch');
	const hostId = ctx.guard(() => validateUuid(ctx.str('hostId'), 'Host ID'));
	const patchType = ctx.str('patchType', 'patch_package');
	if (patchType !== 'patch_package' && patchType !== 'patch_all') throw client.error('Patch Type must be patch_package or patch_all');
	const dryRun = ctx.bool('dryRun');
	const pendingApproval = ctx.bool('pendingApproval');
	if (dryRun && pendingApproval) throw client.error('Dry Run and Pending Approval cannot be used together');
	const body: TriggerBody = { host_id: hostId, patch_type: patchType, dry_run: dryRun, pending_approval: pendingApproval };
	if (patchType === 'patch_package') {
		const names = ctx.guard(() => [...new Set(toList(ctx.param('packageNames', ''), MAX_PACKAGES_PER_RUN).map(validatePackageName))]);
		if (!names.length) throw client.error('Package Names is required for Selected Packages');
		body.package_names = names;
	}
	if (ctx.bool('runImmediately')) body.schedule_override = 'immediate';
	const skipIfActive = ctx.bool('skipIfRunActive', true);
	const wait = pendingApproval ? undefined : waitSettings(ctx);
	await client.requirePermission('can_manage_patching', 'Trigger Patch');

	if (skipIfActive) {
		const active = blockingRunsByHost(await getActiveRuns(client)).get(hostId) ?? [];
		if (active.length) {
			return data({ host_id: hostId, status: 'skipped', reason: 'run_active', active_runs: active.map(runSummary) });
		}
	}

	const outcome = await triggerRun(client, body);
	switch (outcome.kind) {
		case 'active':
			if (skipIfActive) return data({ host_id: hostId, status: 'skipped', reason: 'run_active', message: outcome.message });
			throw client.error(`PatchMon API error 409: ${outcome.message}`, 'Wait for the active run to finish or cancel it first.');
		case 'osRefused':
			throw client.error(`PatchMon API error 400: ${outcome.message}`, 'Use All Packages on this host.');
		case 'notFound':
			throw client.error(`PatchMon API error 404: ${outcome.message}`, 'Check the Host ID.');
		case 'rejected':
			throw client.error(`PatchMon API error 400: ${outcome.message}`);
	}
	const result: IDataObject = {
		...outcome.data,
		host_id: hostId,
		patch_type: patchType,
		package_names: body.package_names ?? [],
		dry_run: dryRun,
		pending_approval: pendingApproval,
		schedule_override: body.schedule_override ?? null,
	};
	return data(await maybeWait(ctx, result, wait));
}

async function approveRun(ctx: OperationContext): Promise<OperationResult> {
	const client = ctx.client;
	const path = ctx.guard(() => runPath(ctx.str('runId'), 'approve'));
	const wait = waitSettings(ctx);
	await client.requirePermission('can_manage_patching', 'Approve Run');
	const body = ctx.bool('runImmediately') ? { schedule_override: 'immediate' } : undefined;
	const answer = await client.session<IDataObject>('POST', path, { body, permission: 'can_manage_patching' });
	return data(await maybeWait(ctx, answer ?? {}, wait));
}

async function cancelRun(ctx: OperationContext): Promise<OperationResult> {
	const runId = ctx.guard(() => validateUuid(ctx.str('runId'), 'Run ID'));
	await ctx.client.requirePermission('can_manage_patching', 'Cancel Run');
	const answer = await ctx.client.session<IDataObject>('POST', runPath(runId, 'stop'), { permission: 'can_manage_patching' });
	return data({ run_id: runId, cancelled: answer?.ok === true, cancelled_via: answer?.cancelled_via ?? null });
}

async function getRuns(ctx: OperationContext): Promise<OperationResult> {
	const filters = ctx.collection('runFilters');
	const sort = ctx.collection('runSort');
	const limit = ctx.limit() ?? MAX_LIST_ENTRIES;
	const include = ctx.bool('includeOutput', true);
	const qs: IDataObject = ctx.guard(() => ({
		host_id: filters.hostId ? validateUuid(filters.hostId, 'Host ID') : undefined,
		status: filters.status ? String(filters.status) : undefined,
		patch_type: filters.patchType === 'patch_all' || filters.patchType === 'patch_package' ? filters.patchType : undefined,
		sort_by: ['created_at', 'started_at', 'completed_at', 'status'].includes(String(sort.sortBy)) ? sort.sortBy : 'created_at',
		sort_dir: sort.sortDir === 'asc' ? 'asc' : 'desc',
	}));
	if (qs.status !== undefined && !RUN_STATUS_VALUES.has(String(qs.status))) throw ctx.client.error('Invalid run status filter');
	const rows: IDataObject[] = [];
	for (let page = 0; page < MAX_POLL_ITERATIONS && rows.length < limit; page++) {
		const size = Math.min(RUNS_PAGE_SIZE, limit - rows.length);
		const answer = await ctx.client.session<IDataObject>('GET', `${PATCHING_PATH}/runs`, {
			qs: { ...qs, limit: size, offset: rows.length },
			permission: 'can_view_hosts',
		});
		if (!answer || !Array.isArray(answer.runs)) throw ctx.client.error('Unexpected answer from PatchMon for the patch runs');
		const runs = answer.runs as IDataObject[];
		rows.push(...runs);
		const total = Number((answer.pagination as IDataObject | undefined)?.total ?? 0);
		// A page can be shorter than requested: rely on total
		if (runs.length === 0 || rows.length >= total) break;
	}
	return list(applyLimit(rows, limit).map((r) => withoutOutput(r, include)));
}

export const patchingHandlers: ResourceHandlers = {
	triggerPatch,
	patchSecurityUpdates: async (ctx) => {
		const result = await patchSecurityUpdates(ctx);
		return Array.isArray(result) ? items(result) : data(result);
	},
	approveRun,
	cancelRun,
	getRuns,

	getActiveRuns: async (ctx) => {
		const limit = ctx.limit();
		const hostId = ctx.str('activeHostId');
		const id = hostId ? ctx.guard(() => validateUuid(hostId, 'Host ID')) : '';
		const include = ctx.bool('includeOutput', true);
		const runs = (await getActiveRuns(ctx.client)).filter((r) => !id || String(r.host_id).toLowerCase() === id);
		return list(applyLimit(runs, limit).map((r) => withoutOutput({ ...r, blocks_new_runs: BLOCKING_STATUSES.has(String(r.status)) }, include)));
	},

	getRun: async (ctx) => data(withoutOutput(await getRun(ctx.client, ctx.str('runId')), ctx.bool('includeOutput', true))),

	previewRun: async (ctx) => {
		const hostId = ctx.guard(() => validateUuid(ctx.str('hostId'), 'Host ID'));
		return data(await ctx.client.session('GET', `${PATCHING_PATH}/preview-run`, { qs: { host_id: hostId }, permission: 'can_view_hosts' }));
	},
};
