export interface Session {
	id: string;
	created_at: string;
	expires_at: string;
	callback_url: string;
	client_cert_pem: string;
	client_key_pem: string;
	cert_cn: string;
	ca_cert_pem: string;
}

export interface CertChainEntry {
	subject: string;
	issuer: string;
	not_after: string;
	key_type: string;
	key_bits: number;
	dns_names?: string[];
}

export interface InspectionReport {
	handshake_ok: boolean;
	failure_code?: string;
	failure_reason?: string;
	expected?: {
		client_auth?: string;
		trusted_ca?: string;
	};
	presented?: {
		tls_version?: string;
		cipher_suite?: string;
		cert_chain?: CertChainEntry[];
	};
	hints?: string[];
}

export interface ProbeResult {
	url: string;
	status_code: number;
	duration_ms: number;
	error?: string;
	inspection?: InspectionReport;
}

export interface CallRecord {
	id: number;
	session_id: string;
	created_at: string;
	callback_url: string;
	test_mode: string;
	status_code: number;
	duration_ms: number;
	error?: string;
	probe_result?: ProbeResult;
}

export interface InboundRequest {
	id: number;
	session_id: string;
	created_at: string;
	method: string;
	path: string;
	status_code: number;
	latency_ms: number;
	handshake_ok: boolean;
	failure_code?: string;
	failure_reason?: string;
	report?: InspectionReport;
}

export interface CertInfo {
	cn: string;
	issuer: string;
	not_after: string;
	dns_names?: string[];
	pem?: string;
	key_pem?: string;
}

export interface CertsResponse {
	ca?: CertInfo;
	server?: CertInfo;
	client?: CertInfo;
}

export interface StatusResponse {
	mode: string;
	started_at: string;
	persist_path?: string;
	mtls_port?: number;
}

export interface MonitorEntry {
	id: string;
	timestamp: string;
	method: string;
	path: string;
	status: number;
	latency_ms: number;
	cert_cn?: string;
	inspection?: InspectionReport;
}

export interface TestResult {
	status_code?: number;
	duration_ms?: number;
	error?: string;
	probe_result?: ProbeResult;
}
