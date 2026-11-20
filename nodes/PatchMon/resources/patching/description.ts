import type { INodeProperties } from 'n8n-workflow';

import { idField, returnAllLimit, splitIntoItems } from '../../shared/descriptions';
import { MAX_HOSTS_PER_RUN, MAX_POLL_INTERVAL_SECONDS, MAX_WAIT_SECONDS, MIN_POLL_INTERVAL_SECONDS } from '../../shared/security';

const R = 'patching';

const RUN_STATUSES = [
	{ name: 'Active (Queued, Validating or Running)', value: 'active' },
	{ name: 'Agent Disconnected', value: 'agent_disconnected' },
	{ name: 'Approved', value: 'approved' },
	{ name: 'Cancelled', value: 'cancelled' },
	{ name: 'Completed', value: 'completed' },
	{ name: 'Failed', value: 'failed' },
	{ name: 'Pending Approval', value: 'pending_approval' },
	{ name: 'Pending Validation', value: 'pending_validation' },
	{ name: 'Queued', value: 'queued' },
	{ name: 'Running', value: 'running' },
	{ name: 'Scheduled', value: 'scheduled' },
	{ name: 'Timed Out', value: 'timed_out' },
	{ name: 'Validated', value: 'validated' },
];

export const patchingDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'getRuns',
		options: [
			{
				name: 'Approve Run',
				value: 'approveRun',
				action: 'Approve a patch run',
				description:
					'Approve a run that waits for approval or a finished dry run: PatchMon then INSTALLS UPDATES on the host. Use only when the user explicitly asks to approve this run.',
			},
			{
				name: 'Cancel Run',
				value: 'cancelRun',
				action: 'Cancel a patch run',
				description:
					'Cancel a scheduled, queued, waiting or running patch run (a running one is stopped on the host). Use only when the user explicitly asks to cancel this run.',
			},
			{ name: 'Get Active Runs', value: 'getActiveRuns', action: 'Get active patch runs', description: 'List runs not finished yet: scheduled, queued, running or waiting for validation or approval' },
			{ name: 'Get Run', value: 'getRun', action: 'Get a patch run', description: 'Get a patch run with its status, output and packages' },
			{ name: 'Get Runs', value: 'getRuns', action: 'Get many patch runs', description: 'List patch runs, filtered by host, status or type' },
			{
				name: 'Patch Security Updates',
				value: 'patchSecurityUpdates',
				action: 'Patch pending security updates',
				description:
					'INSTALLS the pending security updates on one or more hosts (one patch run per host, following its patch policy). Use only when the user explicitly asks to install security updates; use Dry Run to only list what would be started.',
			},
			{
				name: 'Preview Run',
				value: 'previewRun',
				action: 'Preview when a patch run would start',
				description: 'Show the patch policy of a host and when a run triggered now would start. Starts nothing.',
			},
			{
				name: 'Trigger Patch',
				value: 'triggerPatch',
				action: 'Trigger a patch run',
				description:
					'Start a patch run that INSTALLS UPDATES on a host (selected packages or all packages), unless Dry Run or Pending Approval is set. Use only when the user explicitly asks to patch this host.',
			},
		],
	},
	idField(R, ['triggerPatch', 'previewRun'], 'hostId', 'Host ID', 'UUID of the host in PatchMon'),
	idField(R, ['getRun', 'approveRun', 'cancelRun'], 'runId', 'Run ID', 'UUID of the patch run'),

	// Trigger Patch
	{
		displayName: 'Patch Type',
		name: 'patchType',
		type: 'options',
		default: 'patch_package',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch'] } },
		options: [
			{ name: 'Selected Packages', value: 'patch_package', description: 'Update only the listed packages (not supported on Arch Linux)' },
			{ name: 'All Packages', value: 'patch_all', description: 'Update every package with a pending update' },
		],
	},
	{
		displayName: 'Package Names',
		name: 'packageNames',
		type: 'string',
		default: '',
		required: true,
		placeholder: 'openssl, libssl3',
		description: 'Packages to update: comma-separated, or an array from an expression (maximum 100)',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch'], patchType: ['patch_package'] } },
	},
	{
		displayName: 'Dry Run',
		name: 'dryRun',
		type: 'boolean',
		default: false,
		description:
			'Whether PatchMon should only simulate the update on the host and report the packages it would change. Linux hosts support it only with Selected Packages. A finished dry run can be approved with Approve Run.',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch'] } },
	},
	{
		displayName: 'Pending Approval',
		name: 'pendingApproval',
		type: 'boolean',
		default: false,
		description: 'Whether to create the run waiting for approval instead of queuing it: nothing runs until someone approves it (Approve Run)',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch'] } },
	},
	{
		displayName: 'Skip If Run Active',
		name: 'skipIfRunActive',
		type: 'boolean',
		default: true,
		description:
			'Whether to start nothing and return "skipped" when the host already has a scheduled, queued, running or waiting run. If disabled, PatchMon still refuses a second queued or running run.',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch'] } },
	},

	// Patch Security Updates
	{
		displayName: 'Hosts',
		name: 'target',
		type: 'options',
		default: 'hostIds',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'] } },
		options: [
			{ name: 'All Hosts', value: 'all', description: 'Every host with pending security updates' },
			{ name: 'Host Groups', value: 'groups', description: 'The hosts of these host groups' },
			{ name: 'Host IDs', value: 'hostIds', description: 'These hosts' },
		],
	},
	{
		displayName: 'Host IDs',
		name: 'hostIds',
		type: 'string',
		default: '',
		required: true,
		description: 'UUIDs of the hosts: comma-separated, or an array from an expression',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'], target: ['hostIds'] } },
	},
	{
		displayName: 'Host Groups',
		name: 'groups',
		type: 'string',
		default: '',
		required: true,
		placeholder: 'Production, Web',
		description: 'Host group IDs or names: comma-separated, or an array from an expression',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'], target: ['groups'] } },
	},
	{
		displayName: 'Dry Run',
		name: 'dryRun',
		type: 'boolean',
		default: false,
		description: 'Whether to start nothing and only return, for every host, the packages that would be patched or why the host would be skipped',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'] } },
	},
	{
		displayName: 'Output',
		name: 'output',
		type: 'options',
		default: 'perHost',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'] } },
		options: [
			{ name: 'One Item per Host', value: 'perHost', description: 'Started, would start, skipped (with reason) or error, for every host' },
			{ name: 'Summary', value: 'summary', description: 'One item with started hosts, started packages, skipped hosts with reasons and errors' },
		],
	},
	{
		displayName: 'Options',
		name: 'securityOptions',
		type: 'collection',
		placeholder: 'Add Option',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'] } },
		options: [
			{
				displayName: 'Exclude Groups',
				name: 'excludeGroups',
				type: 'string',
				default: '',
				description: 'Skip hosts in these host groups (comma-separated IDs or names)',
			},
			{
				displayName: 'Exclude Hosts',
				name: 'excludeHosts',
				type: 'string',
				default: '',
				description: 'Skip these hosts (comma-separated IDs, friendly names or hostnames)',
			},
			{
				displayName: 'Max Hosts',
				name: 'maxHosts',
				type: 'number',
				default: 100,
				typeOptions: { minValue: 1, maxValue: MAX_HOSTS_PER_RUN },
				description: 'Refuse to run when more hosts than this would be considered (protects against a wrong selection)',
			},
		],
	},

	// Shared by Trigger Patch, Patch Security Updates and Approve Run
	{
		displayName: 'Run Immediately',
		name: 'runImmediately',
		type: 'boolean',
		default: false,
		description:
			"Whether to ignore the host's patch policy and run as soon as possible (schedule_override = immediate). If disabled, the run follows the policy (immediately, after a delay or at a fixed time).",
		displayOptions: { show: { resource: [R], operation: ['triggerPatch', 'patchSecurityUpdates', 'approveRun'] } },
	},

	// Wait For Completion (Trigger Patch, Approve Run)
	{
		displayName: 'Wait for Completion',
		name: 'waitForCompletion',
		type: 'boolean',
		default: false,
		description:
			'Whether to wait until the run finishes and return its final state. Waits only when the run starts within Max Wait: a run scheduled later by its patch policy is returned at once with waited = false.',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch', 'approveRun'] } },
	},
	{
		displayName: 'Max Wait (Minutes)',
		name: 'maxWaitMinutes',
		type: 'number',
		default: 30,
		typeOptions: { minValue: 1, maxValue: MAX_WAIT_SECONDS / 60 },
		description: 'Maximum time to wait (maximum 60). The run keeps going in PatchMon after the wait ends.',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch', 'approveRun'], waitForCompletion: [true] } },
	},
	{
		displayName: 'Poll Interval (Seconds)',
		name: 'pollIntervalSeconds',
		type: 'number',
		default: 15,
		typeOptions: { minValue: MIN_POLL_INTERVAL_SECONDS, maxValue: MAX_POLL_INTERVAL_SECONDS },
		description: 'Seconds between status checks (minimum 5)',
		displayOptions: { show: { resource: [R], operation: ['triggerPatch', 'approveRun'], waitForCompletion: [true] } },
	},

	// Get Run
	{
		displayName: 'Include Shell Output',
		name: 'includeOutput',
		type: 'boolean',
		default: true,
		description: 'Whether to include the console output of the run (shell_output), which can be long',
		displayOptions: { show: { resource: [R], operation: ['getRun', 'getRuns', 'getActiveRuns', 'triggerPatch', 'approveRun'] } },
	},

	// Get Runs / Get Active Runs
	{
		displayName: 'Filters',
		name: 'runFilters',
		type: 'collection',
		placeholder: 'Add Filter',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['getRuns'] } },
		options: [
			{ displayName: 'Host ID', name: 'hostId', type: 'string', default: '', description: 'Only runs of this host (UUID)' },
			{
				displayName: 'Patch Type',
				name: 'patchType',
				type: 'options',
				default: 'patch_package',
				options: [
					{ name: 'All Packages', value: 'patch_all' },
					{ name: 'Selected Packages', value: 'patch_package' },
				],
			},
			{ displayName: 'Status', name: 'status', type: 'options', default: 'active', options: RUN_STATUSES },
		],
	},
	{
		displayName: 'Sort',
		name: 'runSort',
		type: 'collection',
		placeholder: 'Add Sort Option',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['getRuns'] } },
		options: [
			{
				displayName: 'Sort By',
				name: 'sortBy',
				type: 'options',
				default: 'created_at',
				options: [
					{ name: 'Completed At', value: 'completed_at' },
					{ name: 'Created At', value: 'created_at' },
					{ name: 'Started At', value: 'started_at' },
					{ name: 'Status', value: 'status' },
				],
			},
			{
				displayName: 'Direction',
				name: 'sortDir',
				type: 'options',
				default: 'desc',
				options: [
					{ name: 'Ascending', value: 'asc' },
					{ name: 'Descending', value: 'desc' },
				],
			},
		],
	},
	{
		displayName: 'Host ID',
		name: 'activeHostId',
		type: 'string',
		default: '',
		description: 'Only active runs of this host (UUID). Leave empty for all hosts.',
		displayOptions: { show: { resource: [R], operation: ['getActiveRuns'] } },
	},
	...returnAllLimit(R, ['getRuns', 'getActiveRuns']),
	splitIntoItems(R, ['getRuns', 'getActiveRuns']),
	{
		displayName: `Patch Security Updates reads hosts and packages through the Integration API, then checks every host before it starts anything: hosts without security updates, with an active or scheduled run, or on Arch Linux (no partial upgrades) are skipped. Maximum ${MAX_HOSTS_PER_RUN} hosts per item.`,
		name: 'securityNotice',
		type: 'notice',
		default: '',
		displayOptions: { show: { resource: [R], operation: ['patchSecurityUpdates'] } },
	},
];
