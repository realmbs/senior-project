<script lang="ts">
	import { TrendingUp, TrendingDown } from 'lucide-svelte';

	interface Props {
		title: string;
		value: string;
		change: string;
		changeType: 'increase' | 'decrease' | 'neutral';
		icon: any;
		color: string;
	}

	let {
		title,
		value,
		change,
		changeType,
		icon,
		color
	}: Props = $props();

	function getChangeColor(changeType: string) {
		switch (changeType) {
			case 'increase': return 'text-threat-safe';
			case 'decrease': return 'text-threat-critical';
			default: return 'text-slate-400';
		}
	}

	function getChangeIcon(changeType: string) {
		switch (changeType) {
			case 'increase': return TrendingUp;
			case 'decrease': return TrendingDown;
			default: return TrendingUp;
		}
	}

	function getIconColorClass(color: string) {
		switch (color) {
			case 'threat-critical': return 'text-threat-critical';
			case 'threat-high': return 'text-threat-high';
			case 'threat-medium': return 'text-threat-medium';
			case 'threat-low': return 'text-threat-low';
			case 'threat-info': return 'text-threat-info';
			case 'threat-safe': return 'text-threat-safe';
			case 'cyber-primary': return 'text-cyber-primary';
			default: return 'text-slate-400';
		}
	}
</script>

<div class="dashboard-card">
	<div class="flex items-center justify-between">
		<div class="flex items-center gap-3">
			<div class="p-2 glass-tertiary rounded-lg">
				<svelte:component this={icon} class="w-5 h-5 {getIconColorClass(color)}" />
			</div>
			<div>
				<h3 class="text-sm font-medium text-slate-400">{title}</h3>
				<div class="text-2xl font-bold text-slate-100 font-mono">{value}</div>
			</div>
		</div>
		<div class="flex items-center gap-1 {getChangeColor(changeType)}">
			<svelte:component this={getChangeIcon(changeType)} class="w-4 h-4" />
			<span class="text-sm font-medium">{change}</span>
		</div>
	</div>
</div>