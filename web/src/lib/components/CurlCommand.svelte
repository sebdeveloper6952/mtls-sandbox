<script lang="ts">
	import { copyText } from '$lib/utils';

	let { command }: { command: string } = $props();

	let copied = $state(false);

	async function handleCopy() {
		const ok = await copyText(command);
		if (ok) {
			copied = true;
			setTimeout(() => (copied = false), 1500);
		}
	}
</script>

<div class="bg-neutral text-neutral-content rounded-lg px-4 py-3 flex gap-3 items-start group relative">
	<span class="text-success font-mono text-sm font-bold select-none shrink-0 mt-px">$</span>
	<pre class="text-sm font-mono flex-1 overflow-x-auto whitespace-pre-wrap leading-relaxed">{command}</pre>
	<button
		class="btn btn-xs btn-ghost text-neutral-content opacity-0 group-hover:opacity-60 hover:!opacity-100 shrink-0 transition-opacity"
		onclick={handleCopy}
	>
		{copied ? 'Copied!' : 'Copy'}
	</button>
</div>
