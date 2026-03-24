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

<div class="flex flex-col items-center justify-center min-h-[calc(100vh-5rem)]">
	<div class="text-center max-w-3xl space-y-8">
		<h1 class="text-5xl md:text-7xl font-bold tracking-tight leading-tight">
			Test your <span class="text-primary">mTLS</span> configuration
		</h1>
		<p class="text-lg text-base-content/50 max-w-xl mx-auto">
			Validate client certificates, server enforcement, and TLS handshakes — both directions, in
			real time.
		</p>
		<div>
			<button
				class="btn btn-primary btn-lg font-semibold tracking-wide"
				disabled={creating}
				onclick={handleCreate}
			>
				{creating ? 'Creating...' : 'CREATE SESSION'}
				{#if !creating}
					<svg
						xmlns="http://www.w3.org/2000/svg"
						class="h-5 w-5 ml-1"
						viewBox="0 0 24 24"
						fill="none"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					>
						<line x1="5" y1="12" x2="19" y2="12" />
						<polyline points="12 5 19 12 12 19" />
					</svg>
				{/if}
			</button>
		</div>
		{#if error}
			<div class="alert alert-error text-sm max-w-md mx-auto">{error}</div>
		{/if}

		<div
			class="flex flex-col md:flex-row gap-12 pt-16 text-left max-w-2xl mx-auto text-sm text-base-content/60"
		>
			<div class="flex-1 space-y-2">
				<div class="font-mono text-xs font-bold text-base-content/40 uppercase tracking-widest">
					Client Auth &#8594;
				</div>
				<p>
					Your app connects to an mTLS server. Get a session certificate, configure your client, and
					watch handshake results live.
				</p>
			</div>
			<div class="flex-1 space-y-2">
				<div class="font-mono text-xs font-bold text-base-content/40 uppercase tracking-widest">
					&#8592; Server Auth
				</div>
				<p>
					Your server enforces client certs. Trust our CA, set your URL, and we'll call you with
					valid, invalid, and missing credentials.
				</p>
			</div>
		</div>
	</div>
</div>
