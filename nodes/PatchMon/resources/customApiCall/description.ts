import type { INodeProperties } from 'n8n-workflow';

import { splitIntoItems } from '../../shared/descriptions';

const R = 'customApiCall';
const show = { resource: [R], operation: ['call'] };

export const customApiCallDescription: INodeProperties[] = [
	{
		displayName: 'Operation',
		name: 'operation',
		type: 'options',
		noDataExpression: true,
		displayOptions: { show: { resource: [R] } },
		default: 'call',
		options: [
			{
				name: 'Call',
				value: 'call',
				action: 'Make a custom API call',
				description:
					'Send a request to a PatchMon endpoint. POST, PUT, PATCH and DELETE requests CHANGE DATA or START PATCH RUNS: use them only when the user explicitly asks. Prefer the dedicated operations.',
			},
		],
	},
	{
		displayName: 'Access',
		name: 'access',
		type: 'options',
		default: 'integration',
		displayOptions: { show },
		options: [
			{
				name: 'Integration API',
				value: 'integration',
				description: 'Paths under /api/v1/api/, with the Integration API token (Basic Auth)',
			},
			{
				name: 'Service User Session',
				value: 'session',
				description: 'Other paths under /api/v1/ (the web UI API), with the service user',
			},
		],
	},
	{
		displayName:
			'The path is relative to the Base URL and must match the access type. Absolute URLs, traversal and paths outside /api/v1 are refused before sending; so are sign-in, session and two-factor routes. The web UI API is internal to PatchMon and can change between versions.',
		name: 'customNotice',
		type: 'notice',
		default: '',
		displayOptions: { show },
	},
	{
		displayName: 'Method',
		name: 'method',
		type: 'options',
		default: 'GET',
		options: [
			{ name: 'DELETE', value: 'DELETE' },
			{ name: 'GET', value: 'GET' },
			{ name: 'PATCH', value: 'PATCH' },
			{ name: 'POST', value: 'POST' },
			{ name: 'PUT', value: 'PUT' },
		],
		displayOptions: { show },
	},
	{
		displayName: 'Path',
		name: 'path',
		type: 'string',
		default: '',
		required: true,
		placeholder: '/api/v1/api/hosts',
		description: 'Path relative to the Base URL, for example /api/v1/api/hosts/{ID}/package_reports or /api/v1/patching/dashboard',
		displayOptions: { show },
	},
	{
		displayName: 'Query Parameters',
		name: 'queryParameters',
		type: 'fixedCollection',
		typeOptions: { multipleValues: true },
		placeholder: 'Add Query Parameter',
		default: {},
		displayOptions: { show },
		options: [
			{
				name: 'parameter',
				displayName: 'Parameter',
				values: [
					{ displayName: 'Name', name: 'name', type: 'string', default: '' },
					{ displayName: 'Value', name: 'value', type: 'string', default: '' },
				],
			},
		],
	},
	{
		displayName: 'Body (JSON)',
		name: 'body',
		type: 'json',
		default: '{}',
		description: 'JSON body for POST, PUT, PATCH and DELETE',
		displayOptions: { show: { ...show, method: ['POST', 'PUT', 'PATCH', 'DELETE'] } },
	},
	splitIntoItems(R, ['call']),
];
