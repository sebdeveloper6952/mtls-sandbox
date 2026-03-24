<script lang="ts">
	import './layout.css';
	import { onMount } from 'svelte';
	import { getStatus } from '$lib/api';
	import { pad } from '$lib/utils';

	let { children } = $props();

	let mode = $state('--');
	let startedAt: Date | null = $state(null);
	let uptime = $state('--:--:--');
	let theme = $state<'lofi' | 'black'>('lofi');
	let version = $state('');

	onMount(() => {
		// Theme init
		const saved = localStorage.getItem('theme');
		if (saved === 'black' || saved === 'lofi') {
			theme = saved;
		} else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
			theme = 'black';
		}
		document.documentElement.setAttribute('data-theme', theme);

		// Fetch status
		getStatus()
			.then((data) => {
				mode = data.mode;
				startedAt = new Date(data.started_at);
				if (data.version) version = data.version;
			})
			.catch(() => {});

		// Fetch latest tag from GitHub as fallback
		if (!version) {
			fetch('https://api.github.com/repos/sebdeveloper6952/mtls-sandbox/tags?per_page=1')
				.then((r) => r.json())
				.then((tags) => {
					if (Array.isArray(tags) && tags.length > 0) {
						version = tags[0].name;
					}
				})
				.catch(() => {});
		}

		// Uptime ticker
		const timer = setInterval(() => {
			if (!startedAt) return;
			const secs = Math.floor((Date.now() - startedAt.getTime()) / 1000);
			const h = Math.floor(secs / 3600);
			const m = Math.floor((secs % 3600) / 60);
			const s = secs % 60;
			uptime = `${pad(h)}:${pad(m)}:${pad(s)}`;
		}, 1000);

		return () => clearInterval(timer);
	});

	function toggleTheme() {
		theme = theme === 'lofi' ? 'black' : 'lofi';
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
	}
</script>

<div class="min-h-screen bg-base-100">
	<!-- GitHub corner - https://github.com/tholman/github-corners -->
	<a
		href="https://github.com/sebdeveloper6952/mtls-sandbox"
		target="_blank"
		rel="noopener"
		class="github-corner fixed top-0 right-0 z-50"
		aria-label="View source on GitHub"
	>
		<svg
			width="80"
			height="80"
			viewBox="0 0 250 250"
			style="fill:currentColor; position:absolute; top:0; border:0; right:0;"
			class="text-base-content"
			aria-hidden="true"
		>
			<path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z" />
			<path
				d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
				fill="currentColor"
				class="text-base-100 octo-arm"
				style="transform-origin:130px 106px"
			/>
			<path
				d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
				fill="currentColor"
				class="text-base-100 octo-body"
			/>
		</svg>
	</a>

	<div class="navbar px-6">
		<div class="flex-1 items-center gap-3">
			<a href="/" class="font-mono text-lg font-bold tracking-tight">mTLS Sandbox</a>
			{#if version}
				<span class="badge badge-ghost font-mono badge-sm">{version}</span>
			{/if}
			<span
				class="badge badge-sm"
				class:badge-error={mode === 'strict'}
				class:badge-outline={mode !== 'strict'}>{mode}</span
			>
			<nav class="ml-2 flex gap-1">
				<a href="/" class="btn btn-ghost btn-sm">Sessions</a>
				<a href="/monitor" class="btn btn-ghost btn-sm">Monitor</a>
			</nav>
		</div>
		<div class="mr-20 flex flex-none items-center gap-4">
			<span class="font-mono text-xs opacity-40">Uptime: {uptime}</span>
			<label class="btn swap btn-circle swap-rotate btn-ghost btn-sm">
				<input type="checkbox" checked={theme === 'black'} onchange={toggleTheme} />
				<svg
					class="swap-off h-5 w-5 fill-current"
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 24 24"
				>
					<path
						d="M5.64,17l-.71.71a1,1,0,0,0,0,1.41,1,1,0,0,0,1.41,0l.71-.71A1,1,0,0,0,5.64,17ZM5,12a1,1,0,0,0-1-1H3a1,1,0,0,0,0,2H4A1,1,0,0,0,5,12Zm7-7a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V4A1,1,0,0,0,12,5ZM5.64,7.05a1,1,0,0,0,.7.29,1,1,0,0,0,.71-.29,1,1,0,0,0,0-1.41l-.71-.71A1,1,0,0,0,4.93,6.34Zm12,.29a1,1,0,0,0,.7-.29l.71-.71a1,1,0,1,0-1.41-1.41L17,5.64a1,1,0,0,0,0,1.41A1,1,0,0,0,17.66,7.34ZM21,11H20a1,1,0,0,0,0,2h1a1,1,0,0,0,0-2Zm-9,8a1,1,0,0,0-1,1v1a1,1,0,0,0,2,0V20A1,1,0,0,0,12,19ZM18.36,17A1,1,0,0,0,17,18.36l.71.71a1,1,0,0,0,1.41,0,1,1,0,0,0,0-1.41ZM12,6.5A5.5,5.5,0,1,0,17.5,12,5.51,5.51,0,0,0,12,6.5Zm0,9A3.5,3.5,0,1,1,15.5,12,3.5,3.5,0,0,1,12,15.5Z"
					/>
				</svg>
				<svg
					class="swap-on h-5 w-5 fill-current"
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 24 24"
				>
					<path
						d="M21.64,13a1,1,0,0,0-1.05-.14,8.05,8.05,0,0,1-3.37.73A8.15,8.15,0,0,1,9.08,5.49a8.59,8.59,0,0,1,.25-2A1,1,0,0,0,8,2.36,10.14,10.14,0,1,0,22,14.05,1,1,0,0,0,21.64,13Zm-9.5,6.69A8.14,8.14,0,0,1,7.08,5.22v.27A10.15,10.15,0,0,0,17.22,15.63a9.79,9.79,0,0,0,2.1-.22A8.11,8.11,0,0,1,12.14,19.73Z"
					/>
				</svg>
			</label>
		</div>
	</div>

	<main class="mx-auto max-w-6xl px-4">
		{@render children()}
	</main>
</div>
