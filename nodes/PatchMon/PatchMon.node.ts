import {
	NodeConnectionTypes,
	NodeOperationError,
	type IExecuteFunctions,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
} from 'n8n-workflow';

import { customApiCallDescription } from './resources/customApiCall/description';
import { customApiCallHandlers } from './resources/customApiCall/execute';
import { hostDescription } from './resources/host/description';
import { hostHandlers } from './resources/host/execute';
import { hostGroupDescription } from './resources/hostGroup/description';
import { hostGroupHandlers } from './resources/hostGroup/execute';
import { patchingDescription } from './resources/patching/description';
import { patchingHandlers } from './resources/patching/execute';
import { patchPolicyDescription } from './resources/patchPolicy/description';
import { patchPolicyHandlers } from './resources/patchPolicy/execute';
import { repositoryDescription } from './resources/repository/description';
import { repositoryHandlers } from './resources/repository/execute';
import { finalize, OperationContext, safeError, type ResourceHandlers } from './shared/engine';
import { PatchMonClient } from './shared/transport';

const HANDLERS: Record<string, ResourceHandlers> = {
	host: hostHandlers,
	hostGroup: hostGroupHandlers,
	repository: repositoryHandlers,
	patching: patchingHandlers,
	patchPolicy: patchPolicyHandlers,
	customApiCall: customApiCallHandlers,
};

export class PatchMon implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'PatchMon',
		name: 'patchMon',
		icon: { light: 'file:../../icons/patchmon.svg', dark: 'file:../../icons/patchmon.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Read PatchMon hosts, packages, groups, repositories and patch policies, and start, approve or cancel patch runs',
		defaults: {
			name: 'PatchMon',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'patchMonApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{ name: 'Custom API Call', value: 'customApiCall', description: 'Any PatchMon endpoint, with the Integration API token or the service user' },
					{ name: 'Host', value: 'host', description: 'Hosts, their packages and statistics (Integration API)' },
					{ name: 'Host Group', value: 'hostGroup', description: 'Host groups (read-only, service user)' },
					{ name: 'Patch Policy', value: 'patchPolicy', description: 'When patch runs execute (read-only, service user)' },
					{ name: 'Patching', value: 'patching', description: 'Patch runs: start, approve, cancel and follow them (service user)' },
					{ name: 'Repository', value: 'repository', description: 'Package repositories (read-only, service user)' },
				],
				default: 'host',
			},
			...hostDescription,
			...hostGroupDescription,
			...repositoryDescription,
			...patchingDescription,
			...patchPolicyDescription,
			...customApiCallDescription,
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const output: INodeExecutionData[] = [];
		let client: PatchMonClient | undefined;

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				client = client ?? (await PatchMonClient.create(this));
				const resource = this.getNodeParameter('resource', itemIndex) as string;
				const operation = this.getNodeParameter('operation', itemIndex) as string;
				const handlers = Object.prototype.hasOwnProperty.call(HANDLERS, resource) ? HANDLERS[resource] : undefined;
				const handler = handlers && Object.prototype.hasOwnProperty.call(handlers, operation) ? handlers[operation] : undefined;
				if (!handler) {
					throw new NodeOperationError(this.getNode(), `Unsupported operation "${operation}" for resource "${resource}"`, { itemIndex });
				}
				const ctx = new OperationContext(this, client, itemIndex);
				output.push(...finalize(ctx, await handler(ctx)));
			} catch (error) {
				const { message, description } = safeError(client, error);
				if (this.continueOnFail()) {
					output.push({
						json: description ? { error: message, details: description } : { error: message },
						pairedItem: { item: itemIndex },
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), message, { itemIndex, description });
			}
		}
		return [output];
	}
}
