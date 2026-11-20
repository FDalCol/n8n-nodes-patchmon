import type { INodeProperties } from 'n8n-workflow';

import { MAX_LIST_ENTRIES } from './security';

export function splitIntoItems(resource: string, operations: string[]): INodeProperties {
	return {
		displayName: 'Split Into Items',
		name: 'splitIntoItems',
		type: 'boolean',
		default: true,
		description: 'Whether to output one item per list entry. If disabled, one item with a "data" array is returned.',
		displayOptions: { show: { resource: [resource], operation: operations } },
	};
}

export function returnAllLimit(resource: string, operations: string[]): INodeProperties[] {
	return [
		{
			displayName: 'Return All',
			name: 'returnAll',
			type: 'boolean',
			default: false,
			description: 'Whether to return all results or only up to a given limit',
			displayOptions: { show: { resource: [resource], operation: operations } },
		},
		{
			displayName: 'Limit',
			name: 'limit',
			type: 'number',
			default: 50,
			typeOptions: { minValue: 1, maxValue: MAX_LIST_ENTRIES },
			description: 'Max number of results to return',
			displayOptions: { show: { resource: [resource], operation: operations, returnAll: [false] } },
		},
	];
}

export function idField(resource: string, operations: string[], name: string, displayName: string, description: string): INodeProperties {
	return {
		displayName,
		name,
		type: 'string',
		default: '',
		required: true,
		description,
		displayOptions: { show: { resource: [resource], operation: operations } },
	};
}
