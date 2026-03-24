<script lang="ts">
	import { onMount } from 'svelte';
	import { getStatus, getCerts, getRequests, getRequestDetail } from '$lib/api';
	import { timeAgo, copyText } from '$lib/utils';
	import type { CertInfo, MonitorEntry, InspectionReport } from '$lib/types';
	import InspectionDetail from '$lib/components/InspectionDetail.svelte';

	let certs: Record<string, CertInfo> = $state({});
	let curlCommands: { label: string; cmd: string }[] = $state([]);
	let entries: MonitorEntry[] = $state([]);
	let selectedEntry: MonitorEntry | null = $state(null);
	let copiedIdx: number | null = $state(null);
	let copiedPem: string | null = $state(null);

	onMount(() => {
		getCerts()
			.then((data) => {
				certs = data as Record<string, CertInfo>;
			})
			.catch(() => {});

		getStatus()
			.then((data) => {
				buildCurlCommands(data.persist_path || './certs', data.mtls_port || 8443);
			})
			.catch(() => {});

		fetchRequests();
		const timer = setInterval(fetchRequests, 2000);
		return () => clearInterval(timer);
	});

	function buildCurlCommands(persistPath: string, port: number) {
		const host = window.location.hostname;
		const base = `https://${host}:${port}`;
		curlCommands = [
			{
				label: 'Test mTLS handshake (strict mode)',
				cmd: `curl --cert ${persistPath}/client.crt --key ${persistPath}/client.key \\\n  --cacert ${persistPath}/ca.crt \\\n  ${base}/`
			},
			{
				label: 'Without client cert (should fail in strict mode)',
				cmd: `curl --cacert ${persistPath}/ca.crt ${base}/`
			},
			{
				label: 'Debug endpoint',
				cmd: `curl --cert ${persistPath}/client.crt --key ${persistPath}/client.key \\\n  --cacert ${persistPath}/ca.crt \\\n  ${base}/debug`
			}
		];
	}

	async function fetchRequests() {
		try {
			entries = await getRequests();
		} catch {}
	}

	async function selectEntry(entry: MonitorEntry) {
		try {
			selectedEntry = await getRequestDetail(entry.id);
		} catch {}
	}

	async function handleCopyCmd(idx: number, cmd: string) {
		const ok = await copyText(cmd);
		if (ok) {
			copiedIdx = idx;
			setTimeout(() => (copiedIdx = null), 1500);
		}
	}

	async function handleCopyPem(pem: string) {
		const ok = await copyText(pem);
		if (ok) {
			copiedPem = pem;
			setTimeout(() => (copiedPem = null), 1500);
		}
	}

	const certRoles = ['ca', 'server', 'client'] as const;
</script>

<div class="space-y-6">
	<!-- Certificates -->
	<div class="collapse collapse-arrow bg-base-200">
		<input type="checkbox" />
		<div class="collapse-title font-bold text-lg">Certificates</div>
		<div class="collapse-content">
			<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
				{#each certRoles as role}
					{@const cert = certs[role]}
					{#if cert}
						<div class="card bg-base-100 shadow-sm">
							<div class="card-body p-4">
								<h3 class="card-title text-base capitalize">{role}</h3>
								<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
									<span class="opacity-60">CN</span>
									<span>{cert.cn || '--'}</span>
									<span class="opacity-60">Issuer</span>
									<span>{cert.issuer || '--'}</span>
									<span class="opacity-60">Expires</span>
									<span>
										{cert.not_after ? new Date(cert.not_after).toLocaleDateString() : '--'}
									</span>
									{#if cert.dns_names?.length}
										<span class="opacity-60">SANs</span>
										<span>{cert.dns_names.join(', ')}</span>
									{/if}
								</div>
								<div class="flex flex-wrap gap-2 mt-2">
									{#if cert.pem}
										<button
											class="btn btn-xs btn-outline"
											onclick={() => handleCopyPem(cert.pem!)}
										>
											{copiedPem === cert.pem ? 'Copied!' : 'Copy PEM'}
										</button>
										<a
											class="btn btn-xs btn-outline"
											href={`/api/certs/${role}`}
											download
										>
											Download
										</a>
									{/if}
									{#if cert.key_pem}
										<button
											class="btn btn-xs btn-outline"
											onclick={() => handleCopyPem(cert.key_pem!)}
										>
											{copiedPem === cert.key_pem ? 'Copied!' : 'Copy Key'}
										</button>
										<a class="btn btn-xs btn-outline" href="/api/certs/client-key" download>
											Download Key
										</a>
									{/if}
								</div>
							</div>
						</div>
					{/if}
				{/each}
			</div>
		</div>
	</div>

	<!-- Quick Test -->
	<div class="collapse collapse-arrow bg-base-200">
		<input type="checkbox" />
		<div class="collapse-title font-bold text-lg">Quick Test</div>
		<div class="collapse-content">
			<div class="space-y-4">
				{#each curlCommands as cmd, i}
					<div class="bg-base-100 rounded-lg p-3">
						<div class="text-sm font-medium opacity-70 mb-1">{cmd.label}</div>
						<div class="flex items-start gap-3">
							<pre class="text-xs flex-1 overflow-x-auto whitespace-pre-wrap">{cmd.cmd}</pre>
							<button
								class="btn btn-xs btn-outline shrink-0"
								onclick={() => handleCopyCmd(i, cmd.cmd)}
							>
								{copiedIdx === i ? 'Copied!' : 'Copy'}
							</button>
						</div>
					</div>
				{/each}
			</div>
		</div>
	</div>

	<!-- Request Log + Detail -->
	<div class="grid grid-cols-1 lg:grid-cols-[1fr_400px] gap-4">
		<div class="card bg-base-200">
			<div class="card-body">
				<h2 class="card-title text-lg">
					Request Log <span class="badge badge-sm">{entries.length}</span>
				</h2>
				<div class="overflow-x-auto">
					<table class="table table-sm">
						<thead>
							<tr>
								<th>Time</th>
								<th>Method</th>
								<th>Path</th>
								<th>Cert CN</th>
								<th>Result</th>
								<th>Latency</th>
							</tr>
						</thead>
						<tbody>
							{#each entries as entry}
								{@const ok = entry.inspection?.handshake_ok ?? false}
								<tr
									class="cursor-pointer hover"
									class:bg-base-300={selectedEntry?.id === entry.id}
									onclick={() => selectEntry(entry)}
								>
									<td>{timeAgo(entry.timestamp)}</td>
									<td>{entry.method}</td>
									<td>{entry.path}</td>
									<td>{entry.cert_cn || 'none'}</td>
									<td>
										<span
											class="badge badge-sm"
											class:badge-success={ok}
											class:badge-error={!ok}
										>
											{ok ? 'PASS' : 'FAIL'}
										</span>
									</td>
									<td>{entry.latency_ms}ms</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
		</div>

		{#if selectedEntry}
			<div class="card bg-base-200">
				<div class="card-body">
					<h2 class="card-title text-lg">Inspection Detail</h2>
					<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm mb-3">
						<span class="opacity-60">Result</span>
						<span
							class="font-bold"
							class:text-success={selectedEntry.inspection?.handshake_ok}
							class:text-error={!selectedEntry.inspection?.handshake_ok}
						>
							{selectedEntry.inspection?.handshake_ok ? 'PASS' : 'FAIL'}
						</span>
						<span class="opacity-60">Request</span>
						<span>{selectedEntry.method} {selectedEntry.path}</span>
						<span class="opacity-60">Status</span>
						<span>{selectedEntry.status}</span>
						<span class="opacity-60">Latency</span>
						<span>{selectedEntry.latency_ms}ms</span>
						{#if selectedEntry.cert_cn}
							<span class="opacity-60">Client CN</span>
							<span>{selectedEntry.cert_cn}</span>
						{/if}
					</div>

					{#if selectedEntry.inspection?.expected}
						<h3 class="font-semibold text-sm mt-2">Expected</h3>
						<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
							<span class="opacity-60">Client Auth</span>
							<span>{selectedEntry.inspection.expected.client_auth || '--'}</span>
							<span class="opacity-60">Trusted CA</span>
							<span>{selectedEntry.inspection.expected.trusted_ca || '--'}</span>
						</div>
					{/if}

					{#if selectedEntry.inspection?.presented}
						<h3 class="font-semibold text-sm mt-2">Presented</h3>
						<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
							<span class="opacity-60">TLS Version</span>
							<span>{selectedEntry.inspection.presented.tls_version || '--'}</span>
							<span class="opacity-60">Cipher Suite</span>
							<span>{selectedEntry.inspection.presented.cipher_suite || '--'}</span>
							{#if selectedEntry.inspection.presented.cert_chain?.length}
								{@const cert = selectedEntry.inspection.presented.cert_chain[0]}
								<span class="opacity-60">Subject</span>
								<span>{cert.subject}</span>
								<span class="opacity-60">Issuer</span>
								<span>{cert.issuer}</span>
								<span class="opacity-60">Expires</span>
								<span>{cert.not_after}</span>
								<span class="opacity-60">Key</span>
								<span>{cert.key_type} {cert.key_bits}-bit</span>
							{/if}
						</div>
					{/if}

					{#if selectedEntry.inspection?.hints?.length}
						<h3 class="font-semibold text-sm mt-2">Hints</h3>
						<ul class="list-disc list-inside text-sm space-y-0.5 opacity-80">
							{#each selectedEntry.inspection.hints as hint}
								<li>{hint}</li>
							{/each}
						</ul>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</div>
