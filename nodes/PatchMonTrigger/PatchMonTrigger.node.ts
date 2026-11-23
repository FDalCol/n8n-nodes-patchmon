import {
	NodeConnectionTypes,
	NodeOperationError,
	type ICredentialDataDecryptedObject,
	type IDataObject,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
	type IPollFunctions,
} from 'n8n-workflow';

import { signInIdentity } from '../PatchMon/shared/auth';
import { getHostPackages, hostName, listHosts, securityUpdates } from '../PatchMon/shared/hosts';
import { FAILED_STATUSES, PATCHING_PATH } from '../PatchMon/shared/patching';
import {
	MAX_STATE_ENTRIES,
	redactString,
	stateKey,
	toList,
	validateGroupRef,
	validateInteger,
	validateUuid,
} from '../PatchMon/shared/security';
import { CREDENTIAL_NAME, PatchMonClient, type SignInFailure } from '../PatchMon/shared/transport';

type EventName = 'newSecurityUpdates' | 'patchRunFinished' | 'patchRunFailed' | 'hostOffline';

interface TriggerState {
	event?: EventName;
	initialized?: boolean;
	seen?: string[];
	signInPause?: SignInPause;
}

/** Hashes only: never the password. */
interface SignInPause {
	status: 401 | 429;
	account: string;
	session: string;
	until?: string;
	reported: boolean;
}

const MAX_HOSTS = 1000;
const RUNS_PER_POLL = 100;
const DEFAULT_SIGN_IN_WAIT_SECONDS = 60;
const MAX_SIGN_IN_WAIT_SECONDS = 24 * 60 * 60;
const SESSION_EVENTS: EventName[] = ['patchRunFinished', 'patchRunFailed'];

/**
 * A wrong password (401) is not retried until the credential changes; a 429 waits as long as
 * PatchMon asks. Otherwise every poll would sign in again and keep PatchMon's sign-in lockout
 * active for the service user.
 */
export function signInPaused(pause: SignInPause, raw: ICredentialDataDecryptedObject, now: number): boolean {
	const identity = signInIdentity(raw);
	if (!identity || identity.account !== pause.account) return false;
	if (pause.status === 401) return identity.session === pause.session;
	return pause.until !== undefined && now < Date.parse(pause.until);
}

function pauseAfter(failure: SignInFailure, raw: ICredentialDataDecryptedObject, previous: SignInPause | undefined, now: number): SignInPause | undefined {
	const identity = signInIdentity(raw);
	if (!identity || (failure.signInStatus !== 401 && failure.signInStatus !== 429)) return undefined;
	const status = failure.signInStatus;
	const wait = Math.min(failure.retryAfterSeconds ?? DEFAULT_SIGN_IN_WAIT_SECONDS, MAX_SIGN_IN_WAIT_SECONDS);
	const reported =
		previous !== undefined && previous.status === status && previous.account === identity.account && previous.session === identity.session;
	return {
		status,
		account: identity.account,
		session: identity.session,
		until: status === 429 ? new Date(now + wait * 1000).toISOString() : undefined,
		reported,
	};
}

interface Snapshot {
	items: IDataObject[];
	sample: IDataObject[];
}

interface Filters {
	hostIds: Set<string>;
	groups: string[];
}

export class PatchMonTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'PatchMon Trigger',
		name: 'patchMonTrigger',
		icon: { light: 'file:../../icons/patchmon.svg', dark: 'file:../../icons/patchmon.dark.svg' },
		group: ['trigger'],
		version: 1,
		subtitle: '={{$parameter["event"]}}',
		description: 'Starts the workflow on new security updates, finished or failed patch runs and offline hosts (polling)',
		defaults: {
			name: 'PatchMon Trigger',
		},
		polling: true,
		inputs: [],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'patchMonApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Event',
				name: 'event',
				type: 'options',
				noDataExpression: true,
				default: 'newSecurityUpdates',
				options: [
					{
						name: 'Host Offline',
						value: 'hostOffline',
						description: 'A host has not contacted PatchMon for a number of minutes (fires once until it reports again)',
					},
					{
						name: 'New Security Updates',
						value: 'newSecurityUpdates',
						description: 'A host has security updates it did not have at the previous poll',
					},
					{
						name: 'Patch Run Failed',
						value: 'patchRunFailed',
						description: 'A patch run ends as failed, timed out or with the agent disconnected (needs the service user)',
					},
					{
						name: 'Patch Run Finished',
						value: 'patchRunFinished',
						description: 'A patch run completes successfully (needs the service user)',
					},
				],
			},
			{
				displayName: 'Offline After (Minutes)',
				name: 'offlineMinutes',
				type: 'number',
				default: 120,
				typeOptions: { minValue: 5, maxValue: 10080 },
				description:
					"Minutes without any contact from the host's agent (report or heartbeat, last_update in PatchMon). The agent reports every 60 minutes by default.",
				displayOptions: { show: { event: ['hostOffline'] } },
			},
			{
				displayName: 'Filters',
				name: 'filters',
				type: 'collection',
				placeholder: 'Add Filter',
				default: {},
				options: [
					{
						displayName: 'Host Groups',
						name: 'groups',
						type: 'string',
						default: '',
						placeholder: 'Production, Web',
						description: 'Only hosts in these host groups (comma-separated IDs or names)',
					},
					{
						displayName: 'Host IDs',
						name: 'hostIds',
						type: 'string',
						default: '',
						description: 'Only these hosts (comma-separated UUIDs)',
					},
					{
						displayName: 'Include Dry Runs',
						name: 'includeDryRuns',
						type: 'boolean',
						default: false,
						description: 'Whether failed dry runs also fire Patch Run Failed',
					},
				],
			},
			{
				displayName: 'Max Hosts Per Poll',
				name: 'maxHosts',
				type: 'number',
				default: 100,
				typeOptions: { minValue: 1, maxValue: MAX_HOSTS },
				description: 'Maximum number of hosts whose packages are read at each poll (one request per host with security updates)',
				displayOptions: { show: { event: ['newSecurityUpdates'] } },
			},
		],
	};

	async poll(this: IPollFunctions): Promise<INodeExecutionData[][] | null> {
		const event = this.getNodeParameter('event') as EventName;
		const manual = this.getMode() === 'manual';
		const state = this.getWorkflowStaticData('node') as TriggerState;
		if (state.event !== event) {
			for (const key of Object.keys(state)) delete (state as IDataObject)[key];
			state.event = event;
		}
		if (!manual && state.signInPause && SESSION_EVENTS.includes(event)) {
			const raw = await this.getCredentials(CREDENTIAL_NAME);
			if (signInPaused(state.signInPause, raw, Date.now())) return null;
		}
		const firstRun = !state.initialized;
		let client: PatchMonClient | undefined;
		let snapshot: Snapshot;
		try {
			client = await PatchMonClient.create(this);
			const filters = readFilters(this, client);
			switch (event) {
				case 'newSecurityUpdates':
					snapshot = await pollSecurityUpdates.call(this, client, state, filters, manual, firstRun);
					break;
				case 'patchRunFinished':
				case 'patchRunFailed':
					snapshot = await pollRuns.call(this, client, state, filters, event, manual, firstRun);
					break;
				case 'hostOffline':
					snapshot = await pollOffline.call(this, client, state, filters, manual, firstRun);
					break;
				default:
					throw new NodeOperationError(this.getNode(), `Unknown event "${String(event)}"`);
			}
		} catch (error) {
			const failure = client?.lastSignInFailure;
			if (!manual && failure) {
				const raw = await this.getCredentials(CREDENTIAL_NAME);
				const pause = pauseAfter(failure, raw, state.signInPause, Date.now());
				if (pause) {
					state.signInPause = { ...pause, reported: true };
					// Reported once: a later failure for the same status and credential stays silent
					if (pause.reported) return null;
				}
			}
			const e = error as { message?: string; description?: string };
			const redact = (s: string) => (client ? client.redact(s) : redactString(s));
			throw new NodeOperationError(this.getNode(), redact(e?.message ?? 'Polling failed'), {
				description: e?.description ? redact(e.description) : undefined,
			});
		}

		if (!manual) delete state.signInPause;
		if (manual) {
			// Test mode: a real example built from current data; the stored state is not changed
			const items = snapshot.sample;
			if (!items.length) return null;
			return [items.map((json) => ({ json: client!.redactValue(json) }))];
		}
		if (firstRun) {
			state.initialized = true;
			return null;
		}
		if (!snapshot.items.length) return null;
		return [snapshot.items.map((json) => ({ json: client!.redactValue(json) }))];
	}
}

function readFilters(ctx: IPollFunctions, client: PatchMonClient): Filters {
	const raw = (ctx.getNodeParameter('filters', {}) ?? {}) as IDataObject;
	return client.guard(() => ({
		hostIds: new Set(toList(raw.hostIds, MAX_HOSTS).map((id) => validateUuid(id, 'Host ID'))),
		groups: toList(raw.groups, 100).map(validateGroupRef),
	}));
}

async function selectedHosts(client: PatchMonClient, filters: Filters): Promise<IDataObject[]> {
	const hosts = await listHosts(client, filters.groups, true);
	return filters.hostIds.size ? hosts.filter((h) => filters.hostIds.has(String(h.id).toLowerCase())) : hosts;
}

function hostFields(host: IDataObject): IDataObject {
	return {
		host_id: host.id,
		host_name: hostName(host),
		hostname: host.hostname ?? '',
		ip: host.ip ?? '',
		os_type: host.os_type ?? '',
		os_version: host.os_version ?? '',
		host_groups: host.host_groups ?? [],
	};
}

/** Deduplicated by host, package and available version. */
async function pollSecurityUpdates(
	this: IPollFunctions,
	client: PatchMonClient,
	state: TriggerState,
	filters: Filters,
	manual: boolean,
	firstRun: boolean,
): Promise<Snapshot> {
	const maxHosts = client.guard(() => validateInteger(this.getNodeParameter('maxHosts', 100), 'Max Hosts Per Poll', 1, MAX_HOSTS));
	const selected = await selectedHosts(client, filters);
	const hosts = selected
		.filter((h) => Number(h.security_updates_count) > 0)
		.sort((a, b) => Number(b.security_updates_count) - Number(a.security_updates_count))
		.slice(0, maxHosts);
	const previous = new Set(state.seen ?? []);
	// Hosts without security updates have none pending: their old keys are dropped, so an
	// update that comes back later fires again
	const checked = new Set<string>(
		selected.filter((h) => !(Number(h.security_updates_count) > 0)).map((h) => stateKey(String(h.id).toLowerCase())),
	);
	const current: string[] = [];
	const items: IDataObject[] = [];
	const sample: IDataObject[] = [];
	for (const host of hosts) {
		const hostKey = stateKey(String(host.id).toLowerCase());
		const answer = await getHostPackages(client, String(host.id), true);
		if (!answer) continue;
		checked.add(hostKey);
		const updates = securityUpdates(answer.packages);
		const fresh: IDataObject[] = [];
		for (const pkg of updates) {
			const key = `${hostKey}:${stateKey(`${String(pkg.name)}|${String(pkg.available_version ?? '')}`)}`;
			current.push(key);
			if (!previous.has(key)) fresh.push(pkg);
		}
		const item = (list: IDataObject[]): IDataObject => ({
			event: 'newSecurityUpdates',
			...hostFields(host),
			security_updates_count: updates.length,
			new_security_updates: list.map((p) => ({
				name: p.name,
				current_version: p.current_version ?? null,
				available_version: p.available_version ?? null,
				category: p.category ?? '',
			})),
			timestamp: new Date().toISOString(),
		});
		if (updates.length && !sample.length) sample.push(item(updates));
		if (fresh.length) items.push(item(fresh));
	}
	if (!manual) {
		// Keys of hosts not read in this poll (filtered out or over the limit) are kept
		const kept = [...previous].filter((k) => !checked.has(k.split(':')[0]));
		state.seen = [...kept, ...current].slice(-MAX_STATE_ENTRIES);
	}
	return { items: manual || firstRun ? [] : items, sample };
}

async function pollRuns(
	this: IPollFunctions,
	client: PatchMonClient,
	state: TriggerState,
	filters: Filters,
	event: 'patchRunFinished' | 'patchRunFailed',
	manual: boolean,
	firstRun: boolean,
): Promise<Snapshot> {
	client.requireServiceUser('The Patch Run events');
	const raw = (this.getNodeParameter('filters', {}) ?? {}) as IDataObject;
	const includeDryRuns = raw.includeDryRuns === true;
	let allowed: Set<string> | undefined;
	if (filters.groups.length) {
		allowed = new Set((await listHosts(client, filters.groups, false)).map((h) => String(h.id).toLowerCase()));
	}
	const singleHost = filters.hostIds.size === 1 ? [...filters.hostIds][0] : undefined;
	const statuses = event === 'patchRunFinished' ? ['completed'] : FAILED_STATUSES;
	const runs: IDataObject[] = [];
	for (const status of statuses) {
		const answer = await client.session<IDataObject>('GET', `${PATCHING_PATH}/runs`, {
			qs: { status, host_id: singleHost, sort_by: 'completed_at', sort_dir: 'desc', limit: RUNS_PER_POLL, offset: 0 },
			permission: 'can_view_hosts',
		});
		if (!answer || !Array.isArray(answer.runs)) throw client.error('Unexpected answer from PatchMon for the patch runs');
		runs.push(...(answer.runs as IDataObject[]));
	}
	const matching = runs
		.filter((r) => typeof r.id === 'string' && statuses.includes(String(r.status)))
		.filter((r) => includeDryRuns || r.dry_run !== true)
		.filter((r) => !filters.hostIds.size || filters.hostIds.has(String(r.host_id).toLowerCase()))
		.filter((r) => !allowed || allowed.has(String(r.host_id).toLowerCase()))
		.sort((a, b) => (Date.parse(String(a.completed_at)) || 0) - (Date.parse(String(b.completed_at)) || 0));
	const seen = new Set(state.seen ?? []);
	const items: IDataObject[] = [];
	for (const run of matching) {
		const key = stateKey(String(run.id));
		if (seen.has(key)) continue;
		seen.add(key);
		items.push(runItem(event, run));
	}
	if (!manual) state.seen = [...seen].slice(-MAX_STATE_ENTRIES);
	const latest = matching[matching.length - 1];
	return { items: manual || firstRun ? [] : items, sample: latest ? [runItem(event, latest)] : [] };
}

function runItem(event: EventName, run: IDataObject): IDataObject {
	const host = (run.hosts ?? {}) as IDataObject;
	return {
		event,
		run_id: run.id,
		host_id: run.host_id,
		host_name: host.friendly_name || host.hostname || run.host_id,
		status: run.status,
		patch_type: run.patch_type,
		package_names: run.package_names ?? (run.package_name ? [run.package_name] : []),
		packages_affected: run.packages_affected ?? [],
		dry_run: run.dry_run === true,
		error_message: run.error_message ?? null,
		triggered_by_username: run.triggered_by_username ?? null,
		started_at: run.started_at || null,
		completed_at: run.completed_at || null,
		created_at: run.created_at || null,
	};
}

/** Fires once per host, again only after it reported. */
async function pollOffline(
	this: IPollFunctions,
	client: PatchMonClient,
	state: TriggerState,
	filters: Filters,
	manual: boolean,
	firstRun: boolean,
): Promise<Snapshot> {
	const minutes = client.guard(() => validateInteger(this.getNodeParameter('offlineMinutes', 120), 'Offline After (Minutes)', 5, 10080));
	const now = Date.now();
	// Hosts that never reported (pending) have no contact to measure
	const hosts = (await selectedHosts(client, filters)).filter((h) => h.status !== 'pending' && h.effective_status !== 'pending');
	const wasOffline = new Set(state.seen ?? []);
	const offline: string[] = [];
	const items: IDataObject[] = [];
	let oldest: IDataObject | undefined;
	const item = (host: IDataObject, last: number): IDataObject => ({
		event: 'hostOffline',
		...hostFields(host),
		last_update: host.last_update ?? null,
		minutes_since_last_contact: last ? Math.floor((now - last) / 60_000) : null,
		offline_after_minutes: minutes,
		is_offline: !last || now - last > minutes * 60_000,
		timestamp: new Date(now).toISOString(),
	});
	const sample: IDataObject[] = [];
	for (const host of hosts) {
		const last = Date.parse(String(host.last_update ?? '')) || 0;
		if (!oldest || last < (Date.parse(String(oldest.last_update ?? '')) || 0)) oldest = host;
		if (last && now - last <= minutes * 60_000) continue;
		const key = stateKey(String(host.id).toLowerCase());
		offline.push(key);
		sample.push(item(host, last));
		if (!wasOffline.has(key)) items.push(item(host, last));
	}
	if (!manual) state.seen = offline.slice(-MAX_STATE_ENTRIES);
	// Test mode with no offline host: the host with the oldest contact, as a real example
	if (!sample.length && oldest) sample.push(item(oldest, Date.parse(String(oldest.last_update ?? '')) || 0));
	return { items: manual || firstRun ? [] : items, sample: sample.slice(0, 10) };
}
