import type { IDataObject, IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';

import { MAX_LIST_ENTRIES, redactString, SecurityError, validateInteger } from './security';
import type { PatchMonClient } from './transport';

export type OperationResult =
	| { kind: 'data'; data: unknown }
	| { kind: 'list'; data: unknown }
	| { kind: 'items'; data: IDataObject[] };

export type OperationHandler = (ctx: OperationContext) => Promise<OperationResult>;

export type ResourceHandlers = Record<string, OperationHandler>;

export const data = (value: unknown): OperationResult => ({ kind: 'data', data: value });
export const list = (value: unknown): OperationResult => ({ kind: 'list', data: value });
export const items = (value: IDataObject[]): OperationResult => ({ kind: 'items', data: value });

export class OperationContext {
	constructor(
		readonly ef: IExecuteFunctions,
		readonly client: PatchMonClient,
		readonly itemIndex: number,
	) {}

	param<T = unknown>(name: string, fallback?: unknown): T {
		return this.ef.getNodeParameter(name, this.itemIndex, fallback) as T;
	}

	str(name: string, fallback = ''): string {
		const v = this.param<unknown>(name, fallback);
		return v === undefined || v === null ? '' : String(v).trim();
	}

	bool(name: string, fallback = false): boolean {
		return this.param<unknown>(name, fallback) === true;
	}

	collection(name: string): IDataObject {
		const raw = this.param<IDataObject>(name, {}) ?? {};
		const out: IDataObject = {};
		for (const [k, v] of Object.entries(raw)) {
			if (v === undefined || v === null || v === '') continue;
			out[k] = typeof v === 'string' ? v.trim() : v;
		}
		return out;
	}

	guard<T>(fn: () => T): T {
		try {
			return fn();
		} catch (error) {
			throw this.client.error((error as Error).message);
		}
	}

	/** Validated also when it comes from an expression. */
	limit(): number | undefined {
		if (this.bool('returnAll', false)) return undefined;
		return this.guard(() => validateInteger(this.param('limit', 50), 'Limit', 1, MAX_LIST_ENTRIES));
	}
}

function toJson(value: unknown): IDataObject {
	if (value === null || value === undefined) return { success: true };
	if (typeof value === 'object' && !Array.isArray(value)) return value as IDataObject;
	if (Array.isArray(value)) return { data: value as IDataObject[] };
	return { value: value as string | number | boolean };
}

export function applyLimit<T>(rows: T[], limit: number | undefined): T[] {
	return rows.slice(0, Math.min(limit ?? MAX_LIST_ENTRIES, MAX_LIST_ENTRIES));
}

export function finalize(ctx: OperationContext, result: OperationResult): INodeExecutionData[] {
	const pairedItem = { item: ctx.itemIndex };
	const wrap = (json: IDataObject): INodeExecutionData => ({ json: ctx.client.redactValue(json), pairedItem });
	if (result.kind === 'data') return [wrap(toJson(result.data))];
	if (result.kind === 'items') return result.data.map(wrap);
	const arr = Array.isArray(result.data) ? result.data : result.data === null || result.data === undefined ? [] : [result.data];
	const split = ctx.param<boolean>('splitIntoItems', true) !== false;
	if (!split) return [wrap({ data: arr as IDataObject[] })];
	return arr.map((entry) =>
		wrap(entry !== null && typeof entry === 'object' && !Array.isArray(entry) ? (entry as IDataObject) : { value: entry as string }),
	);
}

export function safeError(client: PatchMonClient | undefined, error: unknown): { message: string; description?: string } {
	const e = error as { message?: string; description?: string | null };
	let message = typeof e?.message === 'string' && e.message ? e.message : 'Unknown error';
	let description = typeof e?.description === 'string' ? e.description : undefined;
	if (error instanceof SecurityError) description = undefined;
	if (client) {
		message = client.redact(message);
		description = description ? client.redact(description) : undefined;
	} else {
		message = redactString(message);
		description = description ? redactString(description) : undefined;
	}
	return { message, description };
}
