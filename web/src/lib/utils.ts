export function timeAgo(ts: string): string {
	const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
	if (diff < 60) return `${diff}s ago`;
	if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
	return `${Math.floor(diff / 3600)}h ago`;
}

export function pad(n: number): string {
	return n < 10 ? '0' + n : '' + n;
}

export async function copyText(text: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}

export function downloadText(filename: string, content: string): void {
	const a = document.createElement('a');
	a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(content);
	a.download = filename;
	a.click();
}
