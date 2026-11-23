export const REQUEST_TIMEOUT_MS = 60_000;
export const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
export const MAX_POLL_ITERATIONS = 10_000;
/** PatchMon times runs out on its own. */
export const MAX_WAIT_SECONDS = 60 * 60;
export const MIN_POLL_INTERVAL_SECONDS = 5;
export const MAX_POLL_INTERVAL_SECONDS = 600;
export const MAX_STATE_ENTRIES = 10_000;
export const MAX_LIST_ENTRIES = 100_000;
/** PatchMon accepts at most 100 package names per run (maxPatchTargets). */
export const MAX_PACKAGES_PER_RUN = 100;
export const MAX_HOSTS_PER_RUN = 1000;

/** cyrb53: short state keys and fingerprints, not a cryptographic hash. */
export function stateKey(value: string): string {
	let h1 = 0xdeadbeef;
	let h2 = 0x41c6ce57;
	for (let i = 0; i < value.length; i++) {
		const ch = value.charCodeAt(i);
		h1 = Math.imul(h1 ^ ch, 2654435761);
		h2 = Math.imul(h2 ^ ch, 1597334677);
	}
	h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
	h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
	return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

export class SecurityError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'SecurityError';
	}
}

export function normalizeBaseUrl(raw: unknown): string {
	if (typeof raw !== 'string' || raw.trim() === '') {
		throw new SecurityError('Base URL is required (e.g. https://patchmon.example.com)');
	}
	const trimmed = raw.trim().replace(/\/+$/, '');
	if (!URL.canParse(trimmed)) {
		throw new SecurityError('Base URL is not a valid URL (e.g. https://patchmon.example.com)');
	}
	const parsed = new URL(trimmed);
	const protocol = parsed.protocol.toLowerCase();
	if (protocol !== 'https:' && protocol !== 'http:') {
		throw new SecurityError('Base URL must start with http:// or https://');
	}
	if (parsed.username !== '' || parsed.password !== '' || /^[a-z]+:\/\/[^/]*@/i.test(trimmed)) {
		throw new SecurityError('Base URL must not contain credentials');
	}
	if (parsed.search !== '' || trimmed.includes('?')) {
		throw new SecurityError('Base URL must not contain a query string');
	}
	if (parsed.hash !== '' || trimmed.includes('#')) {
		throw new SecurityError('Base URL must not contain a fragment');
	}
	const path = parsed.pathname.replace(/\/+$/, '');
	// The URL parser resolves "/a/../b" itself: the typed path is checked too
	const typedPath = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
	if (
		[path, typedPath].some((p) => p.split('/').some((s) => s === '..' || s === '.')) ||
		/%2e|%2f|%5c|\\/i.test(path + typedPath)
	) {
		throw new SecurityError('Base URL path is not allowed');
	}
	if (/\/api(\/|$)/i.test(path)) {
		throw new SecurityError('Base URL must be the PatchMon address, without /api/v1');
	}
	return `${protocol}//${parsed.host}${path}`;
}

export function hasControlChars(value: string): boolean {
	for (let i = 0; i < value.length; i++) {
		const c = value.charCodeAt(i);
		if (c < 32 || c === 127) return true;
	}
	return false;
}

/** Printable ASCII without spaces: the only characters a header value built from it may carry. */
export function isHeaderSafe(value: string, maxLength: number): boolean {
	return value.length > 0 && value.length <= maxLength && /^[\x21-\x7e]+$/.test(value);
}

/** Names that must never be used as parameter or object keys (prototype pollution). */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function isSafeKey(key: string): boolean {
	return key !== '' && !FORBIDDEN_KEYS.has(key.toLowerCase());
}

/** Also after one round of percent-decoding. */
export function hasTraversal(value: string): boolean {
	const variants = [value];
	try {
		variants.push(decodeURIComponent(value));
	} catch {
		// not valid percent-encoding: only the raw value can be interpreted
	}
	return variants.some((v) => v.split(/[/\\]/).some((part) => /^\.\.?(;.*)?$/.test(part)));
}

const SAFE_PATH = /^[A-Za-z0-9\-._~:@!$&'()*+,=%/]*$/;

/**
 * Percent-escapes allowed in Custom API Call paths: printable ASCII only, never ".", "/", "\",
 * "%" (double encoding) or ";", and never escaped letters, digits or "-_~" (the server decodes
 * them, so they could slip past the route policy).
 */
function hasForbiddenEscape(path: string): boolean {
	for (const m of path.matchAll(/%([0-9a-f]{2})/gi)) {
		const code = parseInt(m[1], 16);
		if (code < 0x20 || code >= 0x7f || [0x25, 0x2e, 0x2f, 0x3b, 0x5c].includes(code)) return true;
		if (/[A-Za-z0-9_~-]/.test(String.fromCharCode(code))) return true;
	}
	return /%(?![0-9a-f]{2})/i.test(path);
}

export function validateApiPath(raw: unknown): string {
	if (typeof raw !== 'string') throw new SecurityError('Path must be a string');
	let path = raw.trim();
	if (path === '') throw new SecurityError('Path is required');
	if (path.length > 2048) throw new SecurityError('Path is too long');
	if (/^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith('//')) {
		throw new SecurityError('Absolute URLs are not allowed, use a path relative to the Base URL (e.g. /api/v1/patching/runs)');
	}
	if (hasControlChars(path) || /[\s\\]/.test(path)) throw new SecurityError('Path contains forbidden characters');
	if (path.includes('?') || path.includes('#')) {
		throw new SecurityError('Path must not contain a query string or fragment, use Query Parameters');
	}
	if (!SAFE_PATH.test(path)) throw new SecurityError('Path contains forbidden characters');
	if (hasForbiddenEscape(path)) throw new SecurityError('Encoded path separators or traversal sequences are not allowed');
	if (!path.startsWith('/')) path = `/${path}`;
	if (path.includes('//')) throw new SecurityError('Empty path segments are not allowed');
	for (const seg of path.split('/')) {
		if (/^\.\.?(;.*)?$/.test(seg)) throw new SecurityError('Path traversal is not allowed');
	}
	if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
	return path;
}

export type AccessType = 'integration' | 'session';

export const API_PREFIX = '/api/v1';
export const INTEGRATION_PREFIX = '/api/v1/api';

export function isIntegrationPath(path: string): boolean {
	return path === INTEGRATION_PREFIX || path.startsWith(`${INTEGRATION_PREFIX}/`);
}

/** gethomepage has its own token type; a node never signs in, out or changes accounts. */
export function isSessionPath(path: string): boolean {
	if (!path.startsWith(`${API_PREFIX}/`) || isIntegrationPath(path)) return false;
	return !/^\/api\/v1\/(gethomepage|auth|tfa|internal)(\/|$)/i.test(path);
}

function safeDecode(value: string): string | undefined {
	try {
		return decodeURIComponent(value);
	} catch {
		return undefined;
	}
}

/** The path, in both its raw and decoded forms, must belong to the chosen access type. */
export function assertAccessPath(access: AccessType, path: string): void {
	const decoded = safeDecode(path);
	if (decoded === undefined) throw new SecurityError('Path contains invalid percent-encoding');
	const ok = (p: string) => (access === 'integration' ? isIntegrationPath(p) : isSessionPath(p));
	if (!ok(path) || !ok(decoded)) {
		throw new SecurityError(
			access === 'integration'
				? 'Integration API paths must start with /api/v1/api/ (e.g. /api/v1/api/hosts)'
				: 'Session paths must start with /api/v1/ and must not be Integration API, gethomepage, sign-in, session or two-factor routes',
		);
	}
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
	return UUID_RE.test(value);
}

/** Host, patch run and patch policy IDs: PatchMon only accepts UUIDs for them. */
export function validateUuid(value: unknown, label: string): string {
	const str = typeof value === 'string' ? value.trim() : '';
	if (str === '') throw new SecurityError(`${label} is required`);
	if (!isUuid(str)) throw new SecurityError(`${label} must be a UUID`);
	return str.toLowerCase();
}

export function validateId(value: unknown, label: string): string {
	const str = typeof value === 'number' ? String(value) : typeof value === 'string' ? value.trim() : '';
	if (str === '') throw new SecurityError(`${label} is required`);
	if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(str)) throw new SecurityError(`${label} is not a valid ID`);
	return str;
}

/** Same rule as PatchMon's packageNameRegex (handler/patching.go). */
export const PACKAGE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._+-]*$/;

export function validatePackageName(value: unknown): string {
	const str = typeof value === 'string' ? value.trim() : '';
	if (str === '' || str.length > 256 || !PACKAGE_NAME_RE.test(str)) {
		throw new SecurityError(`"${str.slice(0, 64)}" is not a valid package name`);
	}
	return str;
}

/** PatchMon splits the group filter on commas. */
export function validateGroupRef(value: string): string {
	const str = value.trim();
	if (str === '' || str.length > 255 || hasControlChars(str) || str.includes(',')) {
		throw new SecurityError(`"${str.slice(0, 64)}" is not a valid host group ID or name`);
	}
	return str;
}

export function validateText(value: unknown, label: string, maxLength = 500, required = true): string {
	const str = typeof value === 'string' ? value.trim() : value === undefined || value === null ? '' : String(value).trim();
	if (required && str === '') throw new SecurityError(`${label} is required`);
	if (str.length > maxLength) throw new SecurityError(`${label} is too long (maximum ${maxLength} characters)`);
	if (hasControlChars(str)) throw new SecurityError(`${label} contains control characters`);
	return str;
}

export function validateInteger(value: unknown, label: string, min: number, max: number): number {
	const n = typeof value === 'number' ? value : Number(String(value ?? '').trim());
	if (!Number.isInteger(n) || n < min || n > max) {
		throw new SecurityError(`${label} must be an integer between ${min} and ${max}`);
	}
	return n;
}

export function toList(value: unknown, maxEntries = MAX_LIST_ENTRIES): string[] {
	const raw = Array.isArray(value) ? value.map((v) => String(v ?? '')) : String(value ?? '').split(/[,\n]/);
	const out = raw.map((s) => s.trim()).filter((s) => s !== '');
	if (out.length > maxEntries) throw new SecurityError(`Too many entries (maximum ${maxEntries})`);
	return out;
}

export const REDACTED = '[REDACTED]';

// Every pattern is bounded so that redaction stays linear on large untrusted text (no ReDoS).
const SECRET_PATTERNS: RegExp[] = [
	/patchmon_ae_[A-Za-z0-9_-]{4,256}/g,
	// Starts only at a word boundary: inside a long run of "eyJeyJ…" every other start fails at once
	/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,1024}/g,
	/((?:Bearer|Basic)\s{1,8})[^\s"',;]{1,4096}/gi,
	/("?(?:password|token|secret|ticket|refresh_token|tfaTicket|token_secret)"?\s{0,8}[:=]\s{0,8})("[^"\n]{0,4096}"|[^\s,;&}"]{1,4096})/gi,
	/(Authorization\s{0,8}[:=]\s{0,8})[^\r\n,;"]{1,4096}/gi,
	/((?:Set-)?Cookie\s{0,8}[:=]\s{0,8})[^\r\n"]{1,4096}/gi,
];

export function redactString(text: string, secrets: readonly string[] = []): string {
	let out = text;
	for (const secret of secrets) {
		if (!secret) continue;
		for (const v of new Set([secret, encodeURIComponent(secret)])) out = out.split(v).join(REDACTED);
	}
	for (const re of SECRET_PATTERNS) {
		out = out.replace(re, (match, prefix?: string) =>
			typeof prefix === 'string' && match.startsWith(prefix) ? `${prefix}${REDACTED}` : REDACTED,
		);
	}
	return out;
}

const SECRET_KEYS = new Set(['password', 'token', 'secret', 'authorization', 'cookie', 'ticket', 'tfaticket']);

function isSecretKey(key: string): boolean {
	const k = key.toLowerCase();
	return SECRET_KEYS.has(k) || k.includes('password') || k.includes('secret') || k.endsWith('token') || k === 'token_key';
}

export function redactValue<T>(value: T, secrets: readonly string[] = [], depth = 0): T {
	if (depth > 32) return (value !== null && typeof value === 'object' ? '[TRUNCATED]' : redactValue(value, secrets, 0)) as T;
	if (typeof value === 'string') return redactString(value, secrets) as unknown as T;
	if (Array.isArray(value)) return value.map((v) => redactValue(v, secrets, depth + 1)) as unknown as T;
	if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			if (k === '__proto__') continue;
			if (isSecretKey(k) && v !== null && v !== undefined && v !== '') out[k] = REDACTED;
			else out[k] = redactValue(v, secrets, depth + 1);
		}
		return out as T;
	}
	return value;
}
