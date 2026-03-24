<script lang="ts">
	import type { InspectionReport } from '$lib/types';

	let {
		report = null,
		error = ''
	}: { report?: InspectionReport | null; error?: string } = $props();
</script>

<div class="p-3 space-y-3 text-sm">
	{#if error}
		<div class="flex gap-2">
			<span class="font-semibold opacity-70">Error:</span>
			<span class="text-error">{error}</span>
		</div>
	{/if}

	{#if report}
		<div class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
			<span class="font-semibold opacity-70">Handshake</span>
			<span class={report.handshake_ok ? 'text-success font-bold' : 'text-error font-bold'}>
				{report.handshake_ok ? 'OK' : 'FAILED'}
			</span>

			{#if report.failure_code}
				<span class="font-semibold opacity-70">Failure</span>
				<span class="text-error">{report.failure_code}</span>
				<span class="font-semibold opacity-70">Reason</span>
				<span>{report.failure_reason}</span>
			{/if}

			{#if report.presented}
				<span class="font-semibold opacity-70">TLS Version</span>
				<span>{report.presented.tls_version || '--'}</span>
				<span class="font-semibold opacity-70">Cipher</span>
				<span>{report.presented.cipher_suite || '--'}</span>

				{#if report.presented.cert_chain?.length}
					{@const cert = report.presented.cert_chain[0]}
					<span class="font-semibold opacity-70">Subject</span>
					<span>{cert.subject}</span>
					<span class="font-semibold opacity-70">Issuer</span>
					<span>{cert.issuer}</span>
					<span class="font-semibold opacity-70">Expires</span>
					<span>{cert.not_after}</span>
					<span class="font-semibold opacity-70">Key</span>
					<span>{cert.key_type} {cert.key_bits}-bit</span>
				{/if}
			{/if}
		</div>

		{#if report.hints?.length}
			<div>
				<span class="font-semibold opacity-70">Hints:</span>
				<ul class="list-disc list-inside mt-1 space-y-0.5 opacity-80">
					{#each report.hints as hint}
						<li>{hint}</li>
					{/each}
				</ul>
			</div>
		{/if}
	{/if}
</div>
