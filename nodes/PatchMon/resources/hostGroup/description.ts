import type { INodeProperties } from 'n8n-workflow';

import { idField, returnAllLimit, splitIntoItems } from '../../shared/descriptions';

const R = 'hostGroup';

export const hostGroupDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'getAll',
		options: [
			{ name: 'Get', value: 'get', action: 'Get a host group', description: 'Get a host group (needs the service user)' },
			{ name: 'Get Hosts', value: 'getHosts', action: 'Get the hosts of a host group', description: 'List the hosts of a host group (needs the service user)' },
			{ name: 'Get Many', value: 'getAll', action: 'Get many host groups', description: 'List host groups with their host count (needs the service user)' },
		],
	},
	idField(R, ['get', 'getHosts'], 'groupId', 'Host Group ID', 'ID of the host group'),
	...returnAllLimit(R, ['getAll', 'getHosts']),
	splitIntoItems(R, ['getAll', 'getHosts']),
];
