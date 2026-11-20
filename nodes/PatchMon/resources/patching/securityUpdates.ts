/**
 * Patch Security Updates: one patch_package run per host, limited to the packages PatchMon flags
 * as security updates.
 *
 * Phase 1 reads everything (Integration API hosts and packages, the service user's view of
 * active runs and package managers). A sign-in failure or an unexpected Integration API answer
 * stops the node here, before any run is started. Phase 2 starts the runs; an error on one host
 * is reported for that host and never stops the others.
 */
import { NodeOperationError, type IDataObject } from 'n8n-workflow';

import type { OperationContext } from '../../shared/engine';
import { getHostPackages, hostInGroups, hostMatches, hostName, listHosts, securityUpdates } from '../../shared/hosts';
import {
	blockingRunsByHost,
	getActiveRuns,
	getHostDetail,
	refusesSelectedPatch,
	runSummary,
	triggerRun,
	type TriggerBody,
} from '../../shared/patching';
import {
	MAX_HOSTS_PER_RUN,
	MAX_PACKAGES_PER_RUN,
	PACKAGE_NAME_RE,
	toList,
	validateGroupRef,
	validateInteger,
	validateUuid,
} from '../../shared/security';

type Status = 'started' | 'would_start' | 'skipped' | 'error';

export type SkipReason = 'no_security_updates' | 'run_active' | 'os_refused' | 'excluded';

interface HostResult extends IDataObject {
	host_id: string;
	host_name: string;
	status: Status;
}

interface Plan {
	host: IDataObject;
	packages: string[];
	/** Security updates PatchMon would refuse (invalid names) or that exceed 100 per run. */
	notIncluded: string[];
}

const ARCH_MESSAGE = 'PatchMon does not patch selected packages on Arch Linux (pacman): partial upgrades are not supported. Use Trigger Patch with All Packages.';

function entry(host: IDataObject, status: Status, extra: IDataObject = {}): HostResult {
	return { host_id: String(host.id), host_name: hostName(host), status, ...extra };
}

function skipped(host: IDataObject, reason: SkipReason, message: string, extra: IDataObject = {}): HostResult {
	return entry(host, 'skipped', { reason, message, ...extra });
}

/** A failure that must stop the whole operation: sign-in, permissions, cancellation. */
function isFatal(ctx: OperationContext, error: unknown): boolean {
	const message = String((error as Error)?.message ?? '');
	return (
		ctx.client.lastSignInFailure !== undefined ||
		ctx.client.isCancelled() ||
		/^PatchMon API error (401|403)\b/.test(message) ||
		/needs the service user/.test(message)
	);
}

function errorMessage(ctx: OperationContext, error: unknown): string {
	return ctx.client.redact(String((error as Error)?.message ?? 'Unknown error')).slice(0, 1000);
}

/** Valid, unique security update names, sorted; at most 100 per run (PatchMon's limit). */
function packagePlan(packages: IDataObject[]): { packages: string[]; notIncluded: string[] } {
	const names = [...new Set(packages.map((p) => String(p.name ?? '').trim()).filter((n) => n !== ''))].sort();
	const valid = names.filter((n) => n.length <= 256 && PACKAGE_NAME_RE.test(n));
	const invalid = names.filter((n) => !valid.includes(n));
	return { packages: valid.slice(0, MAX_PACKAGES_PER_RUN), notIncluded: [...invalid, ...valid.slice(MAX_PACKAGES_PER_RUN)] };
}

export async function patchSecurityUpdates(ctx: OperationContext): Promise<IDataObject | IDataObject[]> {
	const client = ctx.client;
	client.requireServiceUser('Patch Security Updates');
	const target = ctx.str('target', 'hostIds');
	const dryRun = ctx.bool('dryRun');
	const runImmediately = ctx.bool('runImmediately');
	const summary = ctx.str('output', 'perHost') === 'summary';
	const options = ctx.collection('securityOptions');
	const maxHosts = ctx.guard(() => validateInteger(options.maxHosts ?? 100, 'Max Hosts', 1, MAX_HOSTS_PER_RUN));
	const wantedIds =
		target === 'hostIds' ? ctx.guard(() => [...new Set(toList(ctx.param('hostIds', ''), MAX_HOSTS_PER_RUN).map((id) => validateUuid(id, 'Host ID')))]) : [];
	const groups = target === 'groups' ? ctx.guard(() => toList(ctx.param('groups', ''), 100).map(validateGroupRef)) : [];
	if (target === 'hostIds' && !wantedIds.length) throw client.error('Host IDs is required');
	if (target === 'groups' && !groups.length) throw client.error('Host Groups is required');
	if (!['all', 'hostIds', 'groups'].includes(target)) throw client.error('Hosts must be All Hosts, Host IDs or Host Groups');
	const excludeHosts = new Set(ctx.guard(() => toList(options.excludeHosts, MAX_HOSTS_PER_RUN)).map((s) => s.toLowerCase()));
	const excludeGroups = new Set(ctx.guard(() => toList(options.excludeGroups, 100).map(validateGroupRef)).map((s) => s.toLowerCase()));

	// Checked first: without it nothing would be started, so nothing is read either
	if (!dryRun) await client.requirePermission('can_manage_patching', 'Patch Security Updates');

	// Phase 1: reads only. Any failure here (except a host that no longer exists) stops the node.
	const results: HostResult[] = [];
	const hosts = await listHosts(client, groups, true);
	let targets: IDataObject[];
	if (target === 'hostIds') {
		const byId = new Map(hosts.map((h) => [String(h.id).toLowerCase(), h]));
		targets = [];
		for (const id of wantedIds) {
			const host = byId.get(id);
			if (host) targets.push(host);
			else results.push({ host_id: id, host_name: '', status: 'error', message: 'Host not found in PatchMon' });
		}
	} else {
		targets = hosts;
	}

	const candidates: IDataObject[] = [];
	for (const host of targets) {
		if (hostMatches(host, excludeHosts) || hostInGroups(host, excludeGroups)) {
			results.push(skipped(host, 'excluded', 'Excluded by Exclude Hosts or Exclude Groups'));
		} else if (!(Number(host.security_updates_count) > 0)) {
			results.push(skipped(host, 'no_security_updates', 'No pending security updates'));
		} else {
			candidates.push(host);
		}
	}
	if (candidates.length > maxHosts) {
		throw client.error(
			`${candidates.length} hosts have pending security updates, more than Max Hosts (${maxHosts}): nothing was started`,
			'Narrow the selection or raise Max Hosts.',
		);
	}

	const plans: Plan[] = [];
	if (candidates.length) {
		const active = blockingRunsByHost(await getActiveRuns(client));
		for (const host of candidates) {
			const id = String(host.id).toLowerCase();
			const runs = active.get(id);
			if (runs?.length) {
				results.push(skipped(host, 'run_active', 'The host already has a scheduled, queued, running or waiting patch run', { active_runs: runs.map(runSummary) }));
				continue;
			}
			const answer = await getHostPackages(client, id, true);
			if (!answer) {
				results.push(entry(host, 'error', { message: 'Host not found in PatchMon' }));
				continue;
			}
			const plan = packagePlan(securityUpdates(answer.packages));
			if (!plan.packages.length) {
				results.push(skipped(host, 'no_security_updates', 'No security update with a valid package name', { not_included: plan.notIncluded }));
				continue;
			}
			let detail: IDataObject | undefined;
			try {
				detail = await getHostDetail(client, id);
			} catch (error) {
				if (isFatal(ctx, error)) throw new NodeOperationError(client.node, error as Error);
				results.push(entry(host, 'error', { message: errorMessage(ctx, error) }));
				continue;
			}
			if (!detail) {
				results.push(entry(host, 'error', { message: 'Host not found in PatchMon' }));
				continue;
			}
			if (refusesSelectedPatch(detail)) {
				results.push(skipped(host, 'os_refused', ARCH_MESSAGE, { packages: plan.packages }));
				continue;
			}
			plans.push({ host, ...plan });
		}
	}

	// Phase 2: start the runs. An error on one host never stops the others.
	for (const plan of plans) {
		const base = { packages: plan.packages, package_count: plan.packages.length, not_included: plan.notIncluded };
		if (dryRun) {
			results.push(entry(plan.host, 'would_start', base));
			continue;
		}
		const body: TriggerBody = {
			host_id: String(plan.host.id),
			patch_type: 'patch_package',
			package_names: plan.packages,
			dry_run: false,
			pending_approval: false,
		};
		if (runImmediately) body.schedule_override = 'immediate';
		try {
			const outcome = await triggerRun(client, body);
			if (outcome.kind === 'queued') {
				results.push(
					entry(plan.host, 'started', {
						...base,
						patch_run_id: outcome.data.patch_run_id,
						run_at: outcome.data.run_at ?? null,
						message: outcome.data.message ?? '',
					}),
				);
			} else if (outcome.kind === 'active') {
				results.push(skipped(plan.host, 'run_active', outcome.message || 'The host already has an active patch run'));
			} else if (outcome.kind === 'osRefused') {
				results.push(skipped(plan.host, 'os_refused', outcome.message || ARCH_MESSAGE));
			} else {
				results.push(entry(plan.host, 'error', { ...base, message: outcome.message || 'PatchMon refused the patch run' }));
			}
		} catch (error) {
			if (client.isCancelled()) throw new NodeOperationError(client.node, error as Error);
			results.push(entry(plan.host, 'error', { ...base, message: errorMessage(ctx, error) }));
		}
	}

	const out: IDataObject[] = results.map((r) => ({ ...r, dry_run: dryRun }));
	if (!summary) return out;
	const started = out.filter((r) => r.status === 'started' || r.status === 'would_start');
	return {
		dry_run: dryRun,
		hosts_considered: out.length,
		hosts_started: started.length,
		packages_started: started.reduce((n, r) => n + Number(r.package_count ?? 0), 0),
		started: started.map((r) => ({
			host_id: r.host_id,
			host_name: r.host_name,
			patch_run_id: r.patch_run_id ?? null,
			run_at: r.run_at ?? null,
			packages: r.packages,
		})),
		skipped: out.filter((r) => r.status === 'skipped').map((r) => ({ host_id: r.host_id, host_name: r.host_name, reason: r.reason, message: r.message })),
		errors: out.filter((r) => r.status === 'error').map((r) => ({ host_id: r.host_id, host_name: r.host_name, message: r.message })),
	};
}
