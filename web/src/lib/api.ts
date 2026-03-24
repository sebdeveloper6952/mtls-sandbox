import type {
	Session,
	CallRecord,
	InboundRequest,
	StatusResponse,
	CertsResponse,
	MonitorEntry,
	TestResult
} from './types';

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
	const res = await fetch(url, init);
	if (!res.ok) {
		const body = await res.json().catch(() => ({}));
		throw new Error(body.error || `HTTP ${res.status}`);
	}
	return res.json();
}

export function createSession(): Promise<Session> {
	return fetchJSON('/api/sessions', { method: 'POST' });
}

export function getSession(id: string): Promise<Session> {
	return fetchJSON(`/api/sessions/${id}`);
}

export async function updateCallbackURL(id: string, url: string): Promise<void> {
	await fetchJSON(`/api/sessions/${id}`, {
		method: 'PATCH',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ callback_url: url })
	});
}

export function triggerTest(id: string, mode: string): Promise<TestResult> {
	return fetchJSON(`/api/sessions/${id}/test`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ test_mode: mode })
	});
}

export function listCalls(
	id: string,
	limit = 50
): Promise<{ calls: CallRecord[]; total: number }> {
	return fetchJSON(`/api/sessions/${id}/calls?limit=${limit}`);
}

export function listInbound(
	id: string,
	limit = 50
): Promise<{ requests: InboundRequest[]; total: number }> {
	return fetchJSON(`/api/sessions/${id}/inbound?limit=${limit}`);
}

export function getStatus(): Promise<StatusResponse> {
	return fetchJSON('/api/status');
}

export function getCerts(): Promise<CertsResponse> {
	return fetchJSON('/api/certs');
}

export function getRequests(limit = 100): Promise<MonitorEntry[]> {
	return fetchJSON(`/api/requests?limit=${limit}`);
}

export function getRequestDetail(id: string): Promise<MonitorEntry> {
	return fetchJSON(`/api/requests/${id}`);
}
