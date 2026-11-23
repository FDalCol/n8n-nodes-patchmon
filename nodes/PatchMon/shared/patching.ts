import type { IDataObject } from 'n8n-workflow';

import { MAX_POLL_ITERATIONS, validateUuid } from './security';
import type { PatchMonClient } from './transport';

export const PATCHING_PATH = '/api/v1/patching';

/**
 * Runs that block a new one on the same host. PatchMon itself refuses only queued,
 * pending_validation and running (unique index patch_runs_one_active_per_host); scheduled and
 * pending_approval runs would still execute later, so they block too.
 */
export const BLOCKING_STATUSES = new Set(['scheduled', 'queued', 'running', 'pending_validation', 'pending_approval']);

/** validated: a finished dry run. */
export const TERMINAL_STATUSES = new Set([
	'completed',
	'failed',
	'cancelled',
	'timed_out',
	'agent_disconnected',
	'validated',
	'dry_run_completed',
	'approved',
]);

export const FAILED_STATUSES = ['failed', 'timed_out', 'agent_disconnected'];

/** Must match PatchMon's PacmanSelectedPatchUnsupported refusal (store/patching.go). */
export const OS_REFUSAL_RE = /does not support partial upgrades/i;

export function runPath(runId: string, sub = ''): string {
	return `${PATCHING_PATH}/runs/${validateUuid(runId, 'Run ID')}${sub ? `/${sub}` : ''}`;
}

export async function getActiveRuns(client: PatchMonClient): Promise<IDataObject[]> {
	const answer = await client.session<IDataObject>('GET', `${PATCHING_PATH}/runs/active`, { permission: 'can_view_hosts' });
	if (!answer || typeof answer !== 'object' || !Array.isArray(answer.runs)) {
		throw client.error('Unexpected answer from PatchMon for the active patch runs', 'Check that the server runs PatchMon 2.x.');
	}
	return (answer.runs as unknown[]).filter((r): r is IDataObject => !!r && typeof r === 'object');
}

export function blockingRunsByHost(runs: IDataObject[]): Map<string, IDataObject[]> {
	const out = new Map<string, IDataObject[]>();
	for (const run of runs) {
		if (typeof run.host_id !== 'string' || !BLOCKING_STATUSES.has(String(run.status))) continue;
		const key = run.host_id.toLowerCase();
		out.set(key, [...(out.get(key) ?? []), run]);
	}
	return out;
}

export function runSummary(run: IDataObject): IDataObject {
	return {
		id: run.id,
		status: run.status,
		patch_type: run.patch_type,
		dry_run: run.dry_run ?? false,
		scheduled_at: run.scheduled_at || null,
		created_at: run.created_at || null,
	};
}

/** undefined when the host no longer exists (404). */
export async function getHostDetail(client: PatchMonClient, hostId: string): Promise<IDataObject | undefined> {
	const path = `/api/v1/hosts/${client.guard(() => validateUuid(hostId, 'Host ID'))}`;
	const res = await client.request<IDataObject>('session', 'GET', path, { acceptStatus: [404], permission: 'can_view_hosts' });
	if (res.statusCode === 404) return undefined;
	if (!res.data || typeof res.data !== 'object') {
		throw client.error('Unexpected answer from PatchMon for a host', 'Check that the server runs PatchMon 2.x.');
	}
	return res.data;
}

/** A selected-package run on pacman would be a partial upgrade, which PatchMon refuses. */
export function refusesSelectedPatch(host: IDataObject | undefined): boolean {
	return typeof host?.package_manager === 'string' && host.package_manager.toLowerCase() === 'pacman';
}

export interface TriggerBody {
	host_id: string;
	patch_type: 'patch_all' | 'patch_package';
	package_names?: string[];
	dry_run: boolean;
	pending_approval: boolean;
	schedule_override?: 'immediate';
}

export type TriggerOutcome =
	| { kind: 'queued'; data: IDataObject }
	| { kind: 'active'; message: string }
	| { kind: 'osRefused'; message: string }
	| { kind: 'notFound'; message: string }
	| { kind: 'rejected'; message: string };

export async function triggerRun(client: PatchMonClient, body: TriggerBody): Promise<TriggerOutcome> {
	const res = await client.request<IDataObject>('session', 'POST', `${PATCHING_PATH}/trigger`, {
		body,
		acceptStatus: [400, 404, 409],
		permission: 'can_manage_patching',
	});
	const message = client.redact(String((res.data as IDataObject | null)?.error ?? '')).slice(0, 1000);
	if (res.statusCode === 409) return { kind: 'active', message };
	if (res.statusCode === 404) return { kind: 'notFound', message: message || 'Host not found' };
	if (res.statusCode === 400) return OS_REFUSAL_RE.test(message) ? { kind: 'osRefused', message } : { kind: 'rejected', message };
	if (!res.data || typeof res.data !== 'object' || typeof res.data.patch_run_id !== 'string') {
		throw client.error('Unexpected answer from PatchMon after starting a patch run', 'Check the patch runs in the PatchMon web UI.');
	}
	return { kind: 'queued', data: res.data };
}

export async function getRun(client: PatchMonClient, runId: string): Promise<IDataObject> {
	const path = client.guard(() => runPath(runId));
	return await client.session<IDataObject>('GET', path, { permission: 'can_view_hosts' });
}

export interface WaitResult {
	run: IDataObject;
	finished: boolean;
}

export async function waitForRun(client: PatchMonClient, runId: string, maxWaitMs: number, intervalMs: number): Promise<WaitResult> {
	const deadline = Date.now() + maxWaitMs;
	let run = await getRun(client, runId);
	for (let i = 0; i < MAX_POLL_ITERATIONS; i++) {
		if (TERMINAL_STATUSES.has(String(run.status))) return { run, finished: true };
		const left = deadline - Date.now();
		if (left <= 0) break;
		await client.pause(Math.min(intervalMs, left));
		run = await getRun(client, runId);
	}
	return { run, finished: TERMINAL_STATUSES.has(String(run.status)) };
}
