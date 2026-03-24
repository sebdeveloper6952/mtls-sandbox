<script lang="ts">
	import { copyText, downloadText } from '$lib/utils';

	let { label, content, filename }: { label: string; content: string; filename: string } = $props();

	let copied = $state(false);

	async function handleCopy() {
		const ok = await copyText(content);
		if (ok) {
			copied = true;
			setTimeout(() => (copied = false), 1500);
		}
	}

	function handleDownload() {
		downloadText(filename, content);
	}
</script>

<div class="flex flex-col gap-2">
	<div class="flex items-center justify-between">
		<span class="text-xs font-semibold tracking-wider uppercase opacity-50">{label}</span>
		<div class="flex gap-1">
			<button class="btn btn-xs btn-ghost opacity-60 hover:opacity-100" onclick={handleDownload}>
				Download
			</button>
			<button class="btn btn-xs btn-ghost opacity-60 hover:opacity-100" onclick={handleCopy}>
				{copied ? 'Copied!' : 'Copy'}
			</button>
		</div>
	</div>
	<pre class="bg-neutral text-neutral-content text-xs font-mono p-4 rounded-lg overflow-x-auto max-h-48 leading-relaxed">{content}</pre>
</div>
