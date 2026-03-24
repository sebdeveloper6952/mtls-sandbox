<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { getSession, listCalls, listInbound, updateCallbackURL, triggerTest } from '$lib/api';
	import { timeAgo } from '$lib/utils';
	import type { Session, CallRecord, InboundRequest } from '$lib/types';
	import PemBlock from '$lib/components/PemBlock.svelte';
	import CurlCommand from '$lib/components/CurlCommand.svelte';
	import InspectionDetail from '$lib/components/InspectionDetail.svelte';

	let session: Session | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	let activeTab: 'client' | 'server' = $state('client');

	// Client Auth state
	let inbound: InboundRequest[] = $state([]);
	let inboundTotal = $state(0);
	let expandedInbound: Set<number> = $state(new Set());

	// Server Auth state
	let calls: CallRecord[] = $state([]);
	let callsTotal = $state(0);
	let expandedCalls: Set<number> = $state(new Set());
	let callbackUrl = $state('');
	let urlFeedback = $state('');
	let urlFeedbackOk = $state(false);
	let testFeedback = $state('');
	let testFeedbackOk = $state(false);
	let testingMode = $state('');

	const id = $derived(page.params.id);

	const curlCommand = $derived.by(() => {
		if (typeof window === 'undefined') return '';
		const host = window.location.hostname;
		const isLocal = host === 'localhost' || host === '127.0.0.1';
		const base = `https://${host}:8443`;
		let cmd = `curl --cert session.crt --key session.key`;
		if (isLocal) cmd += ` \\\n     --cacert ca.crt`;
		cmd += ` \\\n     ${base}/`;
		return cmd;
	});

	onMount(() => {
		loadSession();

		const timer = setInterval(() => {
			fetchInbound();
			fetchCalls();
		}, 5000);

		return () => clearInterval(timer);
	});

	async function loadSession() {
		loading = true;
		try {
			session = await getSession(id);
			callbackUrl = session.callback_url || '';
			await Promise.all([fetchInbound(), fetchCalls()]);
		} catch {
			error = 'Session not found or expired.';
		} finally {
			loading = false;
		}
	}

	async function fetchInbound() {
		try {
			const data = await listInbound(id);
			inbound = data.requests || [];
			inboundTotal = data.total;
		} catch {}
	}

	async function fetchCalls() {
		try {
			const data = await listCalls(id);
			calls = data.calls || [];
			callsTotal = data.total;
		} catch {}
	}

	async function handleSaveUrl() {
		urlFeedback = '';
		try {
			await updateCallbackURL(id, callbackUrl);
			if (session) session.callback_url = callbackUrl;
			urlFeedback = 'Saved!';
			urlFeedbackOk = true;
		} catch (e) {
			urlFeedback = e instanceof Error ? e.message : 'Failed to save';
			urlFeedbackOk = false;
		}
	}

	async function handleTest(mode: string) {
		testFeedback = '';
		testingMode = mode;
		try {
			const result = await triggerTest(id, mode);
			if (result.error) {
				testFeedback = result.error;
				testFeedbackOk = false;
			} else {
				testFeedback = `HTTP ${result.status_code} in ${result.duration_ms}ms`;
				testFeedbackOk = true;
			}
			await fetchCalls();
		} catch (e) {
			testFeedback = e instanceof Error ? e.message : 'Test failed';
			testFeedbackOk = false;
		} finally {
			testingMode = '';
		}
	}

	function toggleInbound(idx: number) {
		const next = new Set(expandedInbound);
		if (next.has(idx)) next.delete(idx);
		else next.add(idx);
		expandedInbound = next;
	}

	function toggleCall(idx: number) {
		const next = new Set(expandedCalls);
		if (next.has(idx)) next.delete(idx);
		else next.add(idx);
		expandedCalls = next;
	}
</script>

{#if loading}
	<div class="flex justify-center py-20">
		<span class="loading loading-lg loading-spinner"></span>
	</div>
{:else if error}
	<div class="mx-auto mt-12 alert max-w-lg alert-error">
		{error} <a href="/" class="link">Create a new session</a>.
	</div>
{:else if session}
	<div class="space-y-6">
		<!-- Header -->
		<div>
			<h1 class="text-2xl font-bold">
				Session <code class="text-primary">{session.id}</code>
			</h1>
			<div class="mt-1 flex gap-4 text-sm opacity-60">
				<span>CN: <strong>{session.cert_cn}</strong></span>
				<span>Expires: {new Date(session.expires_at).toLocaleString()}</span>
			</div>
		</div>

		<!-- Tabs -->
		<div role="tablist" class="tabs-border tabs">
			<button
				role="tab"
				class="tab"
				class:tab-active={activeTab === 'client'}
				onclick={() => (activeTab = 'client')}
			>
				&#8594; Client Auth
				<span class="ml-1 badge badge-sm">{inboundTotal}</span>
			</button>
			<button
				role="tab"
				class="tab"
				class:tab-active={activeTab === 'server'}
				onclick={() => (activeTab = 'server')}
			>
				&#8592; Server Auth
				<span class="ml-1 badge badge-sm">{callsTotal}</span>
			</button>
		</div>

		<!-- Client Auth Panel -->
		{#if activeTab === 'client'}
			<div class="space-y-6">
				<p class="text-sm text-base-content/70">
					Test that your app correctly presents a client certificate when connecting to an mTLS
					server. Download your credentials, configure your HTTP client, point it at our endpoint,
					and watch the handshake result appear below.
				</p>

				<!-- Credentials -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">Your Credentials</h2>
						<p class="text-sm opacity-60">
							Your app needs both files. Keep the private key secure.
						</p>
						<div class="mt-2 grid grid-cols-1 gap-6 md:grid-cols-2">
							<PemBlock
								label="Certificate"
								content={session.client_cert_pem}
								filename="session.crt"
							/>
							<PemBlock
								label="Private Key"
								content={session.client_key_pem}
								filename="session.key"
							/>
						</div>
					</div>
				</div>

				<!-- Curl -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">Try It Now</h2>
						<p class="text-sm opacity-60">
							Save the files above as <code>session.crt</code> and
							<code>session.key</code>, then run:
						</p>
						<CurlCommand command={curlCommand} />
						{#if typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')}
							<p class="mt-2 text-sm opacity-60">
								Running locally: also download
								<a href="/api/certs/ca" download="ca.crt" class="link">ca.crt</a>
								to verify our server cert, or replace <code>--cacert ca.crt</code> with
								<code>-k</code>.
							</p>
						{/if}
					</div>
				</div>

				<!-- Inbound Log -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">
							Request Log <span class="badge badge-sm">{inboundTotal}</span>
						</h2>
						{#if inbound.length === 0}
							<div class="py-4 text-center text-sm opacity-50">
								No inbound requests yet. Make a request to the mTLS endpoint using this session's
								client cert.
							</div>
						{:else}
							<div class="overflow-x-auto">
								<table class="table table-sm">
									<thead>
										<tr>
											<th>Time</th>
											<th>Method</th>
											<th>Path</th>
											<th>Status</th>
											<th>Handshake</th>
											<th>Latency</th>
										</tr>
									</thead>
									<tbody>
										{#each inbound as req, i}
											<tr class="hover cursor-pointer" onclick={() => toggleInbound(i)}>
												<td>{timeAgo(req.created_at)}</td>
												<td>{req.method}</td>
												<td>{req.path}</td>
												<td>{req.status_code || '--'}</td>
												<td>
													<span
														class="badge badge-sm"
														class:badge-success={req.handshake_ok}
														class:badge-error={!req.handshake_ok}
													>
														{req.handshake_ok ? 'PASS' : 'FAIL'}
													</span>
												</td>
												<td>{req.latency_ms}ms</td>
											</tr>
											{#if expandedInbound.has(i)}
												<tr>
													<td colspan="6" class="bg-base-300/50">
														<InspectionDetail report={req.report} />
													</td>
												</tr>
											{/if}
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					</div>
				</div>
			</div>
		{/if}

		<!-- Server Auth Panel -->
		{#if activeTab === 'server'}
			<div class="space-y-6">
				<p class="text-sm text-base-content/70">
					Test that your server correctly demands and verifies client certificates from callers.
					Follow the steps below — we'll call your server using this session's client cert and show
					you exactly what happened.
				</p>

				<!-- Step 1: Trust CA -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">Step 1 — Trust Our CA</h2>
						<p class="text-sm opacity-60">
							Add this certificate to your server's trusted <em>client</em> CA list (not the regular server
							trust store).
						</p>
						<PemBlock
							label="CA Certificate"
							content={session.ca_cert_pem}
							filename="sandbox-ca.crt"
						/>
						<div class="collapse-arrow collapse mt-2 bg-base-300">
							<input type="checkbox" />
							<div class="collapse-title text-sm font-medium">Configuration examples</div>
							<div class="collapse-content">
								<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
									<div>
										<div class="mb-1 text-xs font-semibold opacity-60">nginx</div>
										<pre
											class="rounded bg-base-100 p-2 text-xs">ssl_client_certificate /etc/nginx/sandbox-ca.crt;
ssl_verify_client on;</pre>
									</div>
									<div>
										<div class="mb-1 text-xs font-semibold opacity-60">Go</div>
										<pre class="rounded bg-base-100 p-2 text-xs">caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caPEM)
tlsCfg := &tls.Config&#123;
    ClientCAs:  caPool,
    ClientAuth: tls.RequireAndVerifyClientCert,
&#125;</pre>
									</div>
								</div>
							</div>
						</div>
					</div>
				</div>

				<!-- Step 2: URL -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">Step 2 — Your Server URL</h2>
						<p class="text-sm opacity-60">
							The HTTPS URL we'll call. Must be publicly reachable — no private IPs.
						</p>
						<div class="join mt-2 w-full">
							<input
								type="url"
								class="input-bordered input join-item flex-1"
								placeholder="https://your-server.example.com"
								bind:value={callbackUrl}
							/>
							<button class="btn join-item btn-primary" onclick={handleSaveUrl}>Save</button>
						</div>
						{#if urlFeedback}
							<div
								class="mt-1 text-sm"
								class:text-success={urlFeedbackOk}
								class:text-error={!urlFeedbackOk}
							>
								{urlFeedback}
							</div>
						{/if}
					</div>
				</div>

				<!-- Step 3: Tests -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">Step 3 — Run Tests</h2>
						<div class="mt-2 grid grid-cols-1 gap-4 md:grid-cols-3">
							<div class="flex flex-col items-center gap-2 text-center">
								<button
									class="btn btn-block btn-primary"
									disabled={testingMode !== ''}
									onclick={() => handleTest('normal')}
								>
									{testingMode === 'normal' ? 'Testing...' : 'Run mTLS Test'}
								</button>
								<p class="text-xs opacity-70">
									Sends our session cert.<br /><strong class="text-success">Should pass.</strong>
								</p>
							</div>
							<div class="flex flex-col items-center gap-2 text-center">
								<button
									class="btn btn-block btn-error"
									disabled={testingMode !== ''}
									onclick={() => handleTest('no_cert')}
								>
									{testingMode === 'no_cert' ? 'Testing...' : 'No Client Cert'}
								</button>
								<p class="text-xs opacity-70">
									Sends no cert at all.<br /><strong class="text-error">Should be rejected.</strong>
								</p>
							</div>
							<div class="flex flex-col items-center gap-2 text-center">
								<button
									class="btn btn-block btn-error"
									disabled={testingMode !== ''}
									onclick={() => handleTest('wrong_ca')}
								>
									{testingMode === 'wrong_ca' ? 'Testing...' : 'Wrong CA'}
								</button>
								<p class="text-xs opacity-70">
									Cert from untrusted CA.<br /><strong class="text-error"
										>Should be rejected.</strong
									>
								</p>
							</div>
						</div>
						{#if testFeedback}
							<div
								class="mt-2 text-sm"
								class:text-success={testFeedbackOk}
								class:text-error={!testFeedbackOk}
							>
								{testFeedback}
							</div>
						{/if}
					</div>
				</div>

				<!-- Call Results -->
				<div class="card bg-base-200">
					<div class="card-body">
						<h2 class="card-title text-lg">
							Test Results <span class="badge badge-sm">{callsTotal}</span>
						</h2>
						{#if calls.length === 0}
							<div class="py-4 text-center text-sm opacity-50">
								No test calls yet. Run a test above!
							</div>
						{:else}
							<div class="overflow-x-auto">
								<table class="table table-sm">
									<thead>
										<tr>
											<th>Time</th>
											<th>Mode</th>
											<th>Status</th>
											<th>Result</th>
											<th>Latency</th>
										</tr>
									</thead>
									<tbody>
										{#each calls as call, i}
											{@const ok = call.probe_result?.inspection?.handshake_ok ?? false}
											{@const hasError = !!call.error}
											<tr class="hover cursor-pointer" onclick={() => toggleCall(i)}>
												<td>{timeAgo(call.created_at)}</td>
												<td>
													<span
														class="badge badge-sm"
														class:badge-ghost={call.test_mode === 'normal'}
														class:badge-warning={call.test_mode !== 'normal'}
													>
														{call.test_mode || 'normal'}
													</span>
												</td>
												<td>{call.status_code || '--'}</td>
												<td>
													<span
														class="badge badge-sm"
														class:badge-success={!hasError && ok}
														class:badge-error={hasError || !ok}
													>
														{hasError ? 'ERROR' : ok ? 'PASS' : 'FAIL'}
													</span>
												</td>
												<td>{call.duration_ms}ms</td>
											</tr>
											{#if expandedCalls.has(i)}
												<tr>
													<td colspan="5" class="bg-base-300/50">
														<InspectionDetail
															report={call.probe_result?.inspection}
															error={call.error}
														/>
													</td>
												</tr>
											{/if}
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					</div>
				</div>
			</div>
		{/if}
	</div>
{/if}
