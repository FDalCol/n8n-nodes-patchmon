import type { INodeProperties } from 'n8n-workflow';

import { idField, returnAllLimit, splitIntoItems } from '../../shared/descriptions';

const R = 'repository';

export const repositoryDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'getAll',
		options: [
			{ name: 'Get', value: 'get', action: 'Get a repository', description: 'Get a package repository and its hosts (needs the service user)' },
			{
				name: 'Get by Host',
				value: 'getByHost',
				action: 'Get the repositories of a host',
				description: 'List the repositories configured on a host (needs the service user)',
			},
			{ name: 'Get Many', value: 'getAll', action: 'Get many repositories', description: 'List package repositories with their host counts (needs the service user)' },
		],
	},
	idField(R, ['get'], 'repositoryId', 'Repository ID', 'ID of the repository'),
	idField(R, ['getByHost'], 'hostId', 'Host ID', 'UUID of the host in PatchMon'),
	{
		displayName: 'Filters',
		name: 'filters',
		type: 'collection',
		placeholder: 'Add Filter',
		default: {},
		displayOptions: { show: { resource: [R], operation: ['getAll'] } },
		options: [
			{ displayName: 'Host ID', name: 'host', type: 'string', default: '', description: 'Only repositories used by this host (UUID)' },
			{ displayName: 'Search', name: 'search', type: 'string', default: '', description: 'Text to search in name and URL' },
			{
				displayName: 'Status',
				name: 'status',
				type: 'options',
				default: 'active',
				options: [
					{ name: 'Active', value: 'active' },
					{ name: 'Inactive', value: 'inactive' },
				],
			},
			{
				displayName: 'Type',
				name: 'type',
				type: 'options',
				default: 'secure',
				options: [
					{ name: 'Secure (HTTPS)', value: 'secure' },
					{ name: 'Insecure (HTTP)', value: 'insecure' },
				],
			},
		],
	},
	...returnAllLimit(R, ['getAll', 'getByHost']),
	splitIntoItems(R, ['getAll', 'getByHost']),
];
