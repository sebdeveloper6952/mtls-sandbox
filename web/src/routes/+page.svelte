<script lang="ts">
	import { goto } from '$app/navigation';
	import { createSession } from '$lib/api';

	let creating = $state(false);
	let error = $state('');

	async function handleCreate() {
		creating = true;
		error = '';
		try {
			const sess = await createSession();
			goto(`/session/${sess.id}`);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to create session';
			creating = false;
		}
	}
</script>

<div class="flex flex-col items-center gap-8 py-12">
	<div class="text-center max-w-2xl space-y-4">
		<h1 class="text-3xl font-bold">Test Your mTLS Configuration</h1>
		<p class="text-base-content/70">
			Create a session to get a unique client certificate. Use it to validate your outgoing mTLS
			setup, or let us call your server to validate your incoming mTLS enforcement.
		</p>
		<button class="btn btn-primary btn-lg" disabled={creating} onclick={handleCreate}>
			{creating ? 'Creating...' : 'Create Session'}
		</button>
		{#if error}
			<div class="alert alert-error text-sm">{error}</div>
		{/if}
	</div>

	<div class="grid grid-cols-1 md:grid-cols-2 gap-6 w-full max-w-3xl">
		<div class="card bg-base-200 shadow-sm">
			<div class="card-body">
				<div class="text-2xl">&#8594;</div>
				<h2 class="card-title">Client Auth</h2>
				<p class="text-sm text-base-content/70">
					Your app connects to an mTLS server. Verify it presents client certs correctly.
				</p>
				<ol class="list-decimal list-inside text-sm space-y-1 mt-2 opacity-80">
					<li>Download your session cert &amp; key</li>
					<li>Configure your HTTP client to use them</li>
					<li>Point your app at our mTLS endpoint</li>
					<li>Watch the handshake result live</li>
				</ol>
			</div>
		</div>

		<div class="card bg-base-200 shadow-sm">
			<div class="card-body">
				<div class="text-2xl">&#8592;</div>
				<h2 class="card-title">Server Auth</h2>
				<p class="text-sm text-base-content/70">
					Your server receives connections. Verify it correctly demands and verifies client certs.
				</p>
				<ol class="list-decimal list-inside text-sm space-y-1 mt-2 opacity-80">
					<li>Trust our CA on your server</li>
					<li>Set your server's HTTPS URL</li>
					<li>We call you with our client cert</li>
					<li>See whether the handshake passed or failed</li>
				</ol>
			</div>
		</div>
	</div>
</div>
