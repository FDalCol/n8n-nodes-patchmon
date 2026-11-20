import type { IDataObject } from 'n8n-workflow';

import { SecurityError } from './security';

/** Decodes the (already buffered) response body; the size is checked again as a safety net. */
export function readBody(body: unknown, maxBytes: number): string {
	if (body === undefined || body === null) return '';
	if (typeof body === 'string') {
		if (Buffer.byteLength(body) > maxBytes) throw new SecurityError('Response too large');
		return body;
	}
	if (Buffer.isBuffer(body) || body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
		const buf = Buffer.isBuffer(body)
			? body
			: body instanceof ArrayBuffer
				? Buffer.from(body)
				: Buffer.from(body.buffer, body.byteOffset, body.byteLength);
		if (buf.length > maxBytes) throw new SecurityError('Response too large');
		return buf.toString('utf8');
	}
	return JSON.stringify(body);
}

export function tooLargeMessage(maxBytes: number): string {
	return `Response too large (more than ${Math.round(maxBytes / 1024 / 1024)} MiB), aborted`;
}

/** A network error described without the request it came from (headers, body). */
export function describeNetworkError(error: unknown, includeRawMessage = true): { message: string; description?: string } {
	const e = error as {
		code?: string;
		message?: string;
		description?: string;
		cause?: { code?: string; message?: string; cause?: { code?: string; message?: string } };
		context?: { data?: { code?: string } };
	};
	const haystack = [
		e?.code,
		e?.cause?.code,
		e?.cause?.cause?.code,
		e?.context?.data?.code,
		e?.message,
		e?.description,
		e?.cause?.message,
		e?.cause?.cause?.message,
	]
		.filter((x) => typeof x === 'string')
		.join(' ');
	if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER|certificate|ERR_TLS_CERT/i.test(haystack)) {
		return {
			message: 'TLS certificate of the PatchMon server is not trusted (self-signed, expired or wrong host name)',
			description: 'Use a trusted certificate on PatchMon or on the reverse proxy in front of it.',
		};
	}
	if (/EPROTO|wrong version number|SSL routines|ERR_SSL/i.test(haystack)) {
		return { message: 'TLS handshake with the PatchMon server failed', description: 'Check whether the Base URL should use http:// or https://.' };
	}
	if (/ECONNREFUSED/.test(haystack)) return { message: 'Connection refused by the PatchMon server', description: 'Check host and port of the Base URL.' };
	if (/ENOTFOUND|EAI_AGAIN/.test(haystack)) return { message: 'PatchMon host not found', description: 'Check the host name of the Base URL.' };
	if (/ETIMEDOUT|ECONNABORTED|timeout/i.test(haystack)) return { message: 'Request to PatchMon timed out' };
	if (/ECONNRESET|socket hang up/i.test(haystack)) return { message: 'Connection to PatchMon was reset' };
	if (/cancel|abort/i.test(haystack)) return { message: 'Request to PatchMon was cancelled' };
	return {
		message: 'Request to PatchMon failed',
		description: includeRawMessage && typeof e?.message === 'string' ? e.message : undefined,
	};
}

/**
 * PatchMon error bodies: {"error": "..."}, {"error": "Access denied", "message": "..."} (scope
 * checks), {"message": "..."} (sign-in lockout).
 */
export function errorDetail(body: unknown): string {
	if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
	const b = body as IDataObject;
	const parts: string[] = [];
	for (const key of ['error', 'message']) {
		const v = b[key];
		if (typeof v === 'string' && v.trim() !== '' && !parts.includes(v.trim())) parts.push(v.trim());
	}
	return parts.join(': ').slice(0, 2000);
}

/** The PatchMon code of a 403 (TFA_ENROLMENT_REQUIRED, PASSWORD_CHANGE_REQUIRED, module_not_available). */
export function errorCode(body: unknown): string {
	if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
	const code = (body as IDataObject).code;
	return typeof code === 'string' ? code.slice(0, 64) : '';
}
