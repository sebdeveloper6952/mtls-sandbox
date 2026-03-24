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
			})
			.catch(() => {});

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
	<div class="navbar bg-base-200 px-4 shadow-sm">
		<div class="flex-1 gap-4">
			<a href="/" class="text-lg font-bold tracking-tight">mTLS Sandbox</a>
			<span class="badge badge-sm" class:badge-error={mode === 'strict'} class:badge-outline={mode !== 'strict'}>{mode}</span>
			<nav class="flex gap-2">
				<a href="/" class="btn btn-ghost btn-sm">Sessions</a>
				<a href="/monitor" class="btn btn-ghost btn-sm">Monitor</a>
			</nav>
		</div>
		<div class="flex-none gap-3 items-center">
			<span class="text-xs font-mono opacity-60">Uptime: {uptime}</span>
			<label class="swap swap-rotate btn btn-ghost btn-sm btn-circle">
				<input type="checkbox" checked={theme === 'black'} onchange={toggleTheme} />
				<!-- sun icon -->
				<svg
					class="swap-off h-5 w-5 fill-current"
					xmlns="http://www.w3.org/2000/svg"
					viewBox="0 0 24 24"
				>
					<path
						d="M5.64,17l-.71.71a1,1,0,0,0,0,1.41,1,1,0,0,0,1.41,0l.71-.71A1,1,0,0,0,5.64,17ZM5,12a1,1,0,0,0-1-1H3a1,1,0,0,0,0,2H4A1,1,0,0,0,5,12Zm7-7a1,1,0,0,0,1-1V3a1,1,0,0,0-2,0V4A1,1,0,0,0,12,5ZM5.64,7.05a1,1,0,0,0,.7.29,1,1,0,0,0,.71-.29,1,1,0,0,0,0-1.41l-.71-.71A1,1,0,0,0,4.93,6.34Zm12,.29a1,1,0,0,0,.7-.29l.71-.71a1,1,0,1,0-1.41-1.41L17,5.64a1,1,0,0,0,0,1.41A1,1,0,0,0,17.66,7.34ZM21,11H20a1,1,0,0,0,0,2h1a1,1,0,0,0,0-2Zm-9,8a1,1,0,0,0-1,1v1a1,1,0,0,0,2,0V20A1,1,0,0,0,12,19ZM18.36,17A1,1,0,0,0,17,18.36l.71.71a1,1,0,0,0,1.41,0,1,1,0,0,0,0-1.41ZM12,6.5A5.5,5.5,0,1,0,17.5,12,5.51,5.51,0,0,0,12,6.5Zm0,9A3.5,3.5,0,1,1,15.5,12,3.5,3.5,0,0,1,12,15.5Z"
					/>
				</svg>
				<!-- moon icon -->
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

	<main class="max-w-6xl mx-auto p-4">
		{@render children()}
	</main>
</div>
