import type { INodeProperties } from 'n8n-workflow';

import { idField, returnAllLimit, splitIntoItems } from '../../shared/descriptions';

const R = 'patchPolicy';

export const patchPolicyDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'getAll',
		options: [
			{
				name: 'Get',
				value: 'get',
				action: 'Get a patch policy',
				description: 'Get a patch policy with its assignments and excluded hosts (needs the service user)',
			},
			{
				name: 'Get Many',
				value: 'getAll',
				action: 'Get many patch policies',
				description: 'List patch policies: when runs execute (immediately, after a delay or at a fixed time) (needs the service user)',
			},
		],
	},
	idField(R, ['get'], 'policyId', 'Policy ID', 'UUID of the patch policy'),
	...returnAllLimit(R, ['getAll']),
	splitIntoItems(R, ['getAll']),
];
