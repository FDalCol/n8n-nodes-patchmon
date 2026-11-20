import type { INodeProperties } from 'n8n-workflow';

import { idField, returnAllLimit, splitIntoItems } from '../../shared/descriptions';

const R = 'host';

export const hostDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'getAll',
		options: [
			{ name: 'Get', value: 'get', action: 'Get a host', description: 'Get OS, agent version and host groups of a host' },
			{
				name: 'Get Many',
				value: 'getAll',
				action: 'Get many hosts',
				description: 'List hosts with update and security counts, filtered by group, status, OS or update state',
			},
			{ name: 'Get Network', value: 'getNetwork', action: 'Get the network of a host', description: 'Get IP, gateway, DNS servers and interfaces of a host' },
			{
				name: 'Get Packages',
				value: 'getPackages',
				action: 'Get the packages of a host',
				description: 'List installed packages of a host, optionally only those with updates or security updates',
			},
			{ name: 'Get Stats', value: 'getStats', action: 'Get the stats of a host', description: 'Count installed, outdated and security packages and repositories of a host' },
			{ name: 'Get System', value: 'getSystem', action: 'Get the system of a host', description: 'Get kernel, CPU, memory, disks, uptime and reboot state of a host' },
		],
	},
	idField(R, ['get', 'getNetwork', 'getPackages', 'getStats', 'getSystem'], 'hostId', 'Host ID', 'UUID of the host in PatchMon'),
	{
		displayName: 'Filters',
		name: 'filters',
		type: 'collection',
		placeholder: 'Add Filter',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['getAll'] } },
		options: [
			{
				displayName: 'Host Groups',
				name: 'groups',
				type: 'string',
				default: '',
				placeholder: 'Production, Web',
				description: 'Only hosts in these groups (comma-separated IDs or names). Filtered by PatchMon.',
			},
			{
				displayName: 'Needs Reboot',
				name: 'needsReboot',
				type: 'boolean',
				default: true,
				description: 'Whether to return only hosts that need (true) or do not need (false) a reboot',
			},
			{
				displayName: 'OS Type',
				name: 'osType',
				type: 'string',
				default: '',
				placeholder: 'Ubuntu',
				description: 'Only hosts whose OS type contains this text (case-insensitive)',
			},
			{
				displayName: 'Reporting State',
				name: 'reportingState',
				type: 'options',
				default: 'reporting',
				options: [
					{ name: 'Overdue', value: 'overdue', description: 'Missed one report interval' },
					{ name: 'Reporting', value: 'reporting', description: 'Reported within the last interval' },
					{ name: 'Stale', value: 'stale', description: 'Missed two report intervals or never reported' },
				],
			},
			{
				displayName: 'Status',
				name: 'status',
				type: 'options',
				default: 'active',
				description: 'Effective status as shown in the PatchMon web UI',
				options: [
					{ name: 'Active', value: 'active' },
					{ name: 'Inactive', value: 'inactive', description: 'Active host that stopped reporting' },
					{ name: 'Pending', value: 'pending', description: 'Enrolled but never reported' },
				],
			},
			{
				displayName: 'Update State',
				name: 'updateState',
				type: 'options',
				default: 'security_required',
				options: [
					{ name: 'Security Updates Pending', value: 'security_required' },
					{ name: 'Up to Date', value: 'up_to_date' },
					{ name: 'Updates Pending', value: 'updates_pending', description: 'Updates pending, none of them security updates' },
				],
			},
		],
	},
	{
		displayName: 'Filters',
		name: 'packageFilters',
		type: 'collection',
		placeholder: 'Add Filter',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['getPackages'] } },
		options: [
			{
				displayName: 'Name Contains',
				name: 'name',
				type: 'string',
				default: '',
				description: 'Only packages whose name contains this text (case-insensitive)',
			},
			{
				displayName: 'Only Security Updates',
				name: 'onlySecurity',
				type: 'boolean',
				default: false,
				description: 'Whether to return only packages with a pending security update (is_security_update)',
			},
			{
				displayName: 'Only With Updates',
				name: 'onlyWithUpdates',
				type: 'boolean',
				default: false,
				description: 'Whether to return only packages with a pending update',
			},
		],
	},
	...returnAllLimit(R, ['getAll', 'getPackages']),
	splitIntoItems(R, ['getAll', 'getPackages']),
];
