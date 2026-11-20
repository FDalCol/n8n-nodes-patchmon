/** Integration API reads (Basic Auth, scope host: get). */
import type { IDataObject } from 'n8n-workflow';

import { validateGroupRef, validateUuid } from './security';
import type { PatchMonClient } from './transport';

export const HOSTS_PATH = '/api/v1/api/hosts';

export function hostPath(hostId: string, sub = ''): string {
	return `${HOSTS_PATH}/${validateUuid(hostId, 'Host ID')}${sub ? `/${sub}` : ''}`;
}

/** The display name of a host: friendly name, else hostname, else ID. */
export function hostName(host: IDataObject): string {
	for (const key of ['friendly_name', 'hostname', 'id']) {
		const v = host[key];
		if (typeof v === 'string' && v.trim() !== '') return v;
	}
	return '';
}

function unexpected(client: PatchMonClient, what: string): Error {
	return client.error(
		`Unexpected answer from the PatchMon Integration API (${what})`,
		'Check that the Base URL points to PatchMon 2.x and that no proxy rewrites the answer.',
	);
}

/**
 * GET /api/v1/api/hosts. `groups` are host group IDs or names (PatchMon resolves both); with
 * `includeStats` every host has OS, status, update and security counts and last_update.
 */
export async function listHosts(client: PatchMonClient, groups: string[] = [], includeStats = true): Promise<IDataObject[]> {
	const refs = client.guardList(groups, validateGroupRef);
	const answer = await client.integration<IDataObject>(HOSTS_PATH, {
		hostgroup: refs.length ? refs.join(',') : undefined,
		include: includeStats ? 'stats' : undefined,
	});
	if (!answer || typeof answer !== 'object' || !Array.isArray(answer.hosts)) throw unexpected(client, 'host list');
	const hosts = answer.hosts as unknown[];
	if (hosts.some((h) => !h || typeof h !== 'object' || typeof (h as IDataObject).id !== 'string')) {
		throw unexpected(client, 'host list');
	}
	return hosts as IDataObject[];
}

export interface HostPackages {
	host: IDataObject;
	packages: IDataObject[];
}

/** GET /api/v1/api/hosts/{id}/packages, or undefined when the host does not exist (404). */
export async function getHostPackages(client: PatchMonClient, hostId: string, updatesOnly: boolean): Promise<HostPackages | undefined> {
	const path = client.guard(() => hostPath(hostId, 'packages'));
	const res = await client.request<IDataObject>('integration', 'GET', path, {
		qs: updatesOnly ? { updates_only: 'true' } : undefined,
		acceptStatus: [404],
	});
	if (res.statusCode === 404) return undefined;
	const answer = res.data;
	if (!answer || typeof answer !== 'object' || !Array.isArray(answer.packages)) throw unexpected(client, 'host packages');
	const packages = (answer.packages as unknown[]).filter((p): p is IDataObject => !!p && typeof p === 'object');
	return { host: (answer.host as IDataObject) ?? { id: hostId }, packages };
}

/** Packages with a pending update flagged as a security update by PatchMon (is_security_update). */
export function securityUpdates(packages: IDataObject[]): IDataObject[] {
	return packages.filter((p) => p.is_security_update === true && p.needs_update === true);
}

/** Case-insensitive match of a host on its ID, friendly name or hostname. */
export function hostMatches(host: IDataObject, refs: Set<string>): boolean {
	for (const key of ['id', 'friendly_name', 'hostname']) {
		const v = host[key];
		if (typeof v === 'string' && v !== '' && refs.has(v.toLowerCase())) return true;
	}
	return false;
}

/** Case-insensitive match of a host on the ID or name of one of its groups. */
export function hostInGroups(host: IDataObject, refs: Set<string>): boolean {
	const groups = Array.isArray(host.host_groups) ? (host.host_groups as IDataObject[]) : [];
	return groups.some((g) =>
		['id', 'name'].some((k) => typeof g?.[k] === 'string' && refs.has(String(g[k]).toLowerCase())),
	);
}
