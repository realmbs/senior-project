<script lang="ts">
	import { TrendingUp, TrendingDown, Activity } from 'lucide-svelte';

	interface Props {
		title: string;
		description: string;
		icon: any;
		severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'safe' | 'unknown';
		status: 'active' | 'ready' | 'processing' | 'offline';
		actions: Array<{ label: string; type: 'primary' | 'secondary' }>;
		stats: Array<{ label: string; value: string }>;
	}

	let {
		title,
		description,
		icon,
		severity,
		status,
		actions,
		stats
	}: Props = $props();

	function getSeverityClass(severity: string) {
		switch (severity) {
			case 'critical': return 'threat-card-critical';
			case 'high': return 'threat-card-high';
			case 'medium': return 'threat-card-medium';
			case 'low': return 'threat-card-low';
			case 'safe': return 'threat-card-safe';
			default: return 'threat-card';
		}
	}

	function getStatusBadge(status: string) {
		switch (status) {
			case 'active': return 'threat-badge-safe';
			case 'ready': return 'threat-badge-info';
			case 'processing': return 'threat-badge-medium';
			case 'offline': return 'threat-badge-critical';
			default: return 'threat-badge-unknown';
		}
	}

	function getStatusIcon(status: string) {
		switch (status) {
			case 'active': return Activity;
			case 'processing': return TrendingUp;
			default: return Activity;
		}
	}
</script>

<div class="{getSeverityClass(severity)} ">
	<!-- Card Header -->
	<div class="flex items-start justify-between mb-4">
		<div class="flex items-center gap-3">
			<div class="p-2 glass-tertiary rounded-lg">
				<svelte:component this={icon} class="w-6 h-6 text-cyber-primary" />
			</div>
			<div>
				<h3 class="text-lg font-semibold text-slate-100">{title}</h3>
				<div class="{getStatusBadge(status)} mt-1">{status}</div>
			</div>
		</div>
		<div class="animate-pulse">
			<svelte:component this={getStatusIcon(status)} class="w-5 h-5 text-slate-400" />
		</div>
	</div>

	<!-- Description -->
	<p class="text-slate-400 text-sm mb-6 leading-relaxed">
		{description}
	</p>

	<!-- Stats Grid -->
	<div class="grid grid-cols-3 gap-4 mb-6">
		{#each stats as stat}
			<div class="text-center">
				<div class="text-lg font-bold text-slate-100 font-mono">{stat.value}</div>
				<div class="text-xs text-slate-400">{stat.label}</div>
			</div>
		{/each}
	</div>

	<!-- Actions -->
	<div class="space-y-2">
		{#each actions as action}
			<button class="{action.type === 'primary' ? 'btn-primary' : 'btn-glass'} w-full">
				{action.label}
			</button>
		{/each}
	</div>
</div>