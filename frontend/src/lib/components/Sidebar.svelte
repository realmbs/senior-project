<script lang="ts">
	import {
		Home,
		Search,
		Zap,
		BarChart3,
		Database,
		Shield,
		Globe,
		FileText,
		Settings,
		ChevronRight,
		Loader2,
		AlertTriangle
	} from 'lucide-svelte';
	import { onMount } from 'svelte';
	import {
		systemStatusStore,
		recentThreatsStore,
		dashboardActions
	} from '$lib/stores/dashboard';

	// Current route - this would normally come from SvelteKit's page store
	let currentRoute = '/';

	// Load dashboard data on mount
	onMount(() => {
		dashboardActions.loadDashboard();
	});

	interface NavItem {
		href: string;
		label: string;
		icon: any;
		badge?: string;
		badgeColor?: string;
	}

	const navItems: NavItem[] = [
		{ href: '/', label: 'Dashboard', icon: Home },
		{ href: '/collect', label: 'Threat Collection', icon: Zap, badge: 'ACTIVE', badgeColor: 'status-online' },
		{ href: '/search', label: 'Search & Analysis', icon: Search },
		{ href: '/enrich', label: 'OSINT Enrichment', icon: Globe },
		{ href: '/analytics', label: 'Analytics', icon: BarChart3 },
		{ href: '/database', label: 'Database', icon: Database },
		{ href: '/reports', label: 'Reports', icon: FileText },
		{ href: '/security', label: 'Security Center', icon: Shield },
	];

	const adminItems: NavItem[] = [
		{ href: '/settings', label: 'Settings', icon: Settings },
	];

	// Helper function to get system status display info
	function getSystemStatusDisplay(status: string) {
		switch (status) {
			case 'healthy':
				return {
					color: 'bg-status-online',
					textColor: 'text-status-online',
					label: 'Online'
				};
			case 'degraded':
				return {
					color: 'bg-status-degraded',
					textColor: 'text-status-degraded',
					label: 'Degraded'
				};
			default:
				return {
					color: 'bg-status-offline',
					textColor: 'text-status-offline',
					label: 'Offline'
				};
		}
	}

	// Helper function to calculate threat severity counts
	function getThreatCounts(threats: any[]) {
		if (!threats || threats.length === 0) {
			return { critical: 0, high: 0, medium: 0, total: 0 };
		}

		const counts = threats.reduce((acc, threat) => {
			const confidence = threat.confidence || 0;
			if (confidence >= 90) acc.critical++;
			else if (confidence >= 70) acc.high++;
			else if (confidence >= 50) acc.medium++;
			return acc;
		}, { critical: 0, high: 0, medium: 0 });

		return {
			...counts,
			total: threats.length
		};
	}
</script>

<aside class="sidebar">
	<div class="p-4 pb-8">
		<!-- Main Navigation -->
		<nav class="space-y-2">
			<!-- Threat Intelligence Section -->
			<div class="mb-6">
				<h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
					Threat Intelligence
				</h3>
				{#each navItems as item}
					<a
						href={item.href}
						class="{currentRoute === item.href ? 'nav-link-active' : 'nav-link'} group"
					>
						<svelte:component this={item.icon} class="w-5 h-5 mr-3" />
						<span class="flex-1">{item.label}</span>
						{#if item.badge}
							<span class="text-xs px-2 py-0.5 rounded-full bg-{item.badgeColor} text-slate-900 font-mono">
								{item.badge}
							</span>
						{/if}
						<ChevronRight class="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
					</a>
				{/each}
			</div>

			<!-- Administration Section -->
			<div class="border-t border-slate-700/50 pt-4 mb-6">
				<h3 class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
					Administration
				</h3>
				{#each adminItems as item}
					<a
						href={item.href}
						class="{currentRoute === item.href ? 'nav-link-active' : 'nav-link'} group"
					>
						<svelte:component this={item.icon} class="w-5 h-5 mr-3" />
						<span class="flex-1">{item.label}</span>
						<ChevronRight class="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
					</a>
				{/each}
			</div>
		</nav>

		<!-- System Status Card -->
		<div class="mt-4 glass-tertiary rounded-lg p-3">
			<div class="flex items-center justify-between mb-3">
				<h4 class="text-sm font-semibold text-slate-200">System Health</h4>
				{#if $systemStatusStore.loading}
					<Loader2 class="w-3 h-3 animate-spin text-slate-400" />
				{/if}
			</div>

			{#if $systemStatusStore.loading}
				<!-- Loading state -->
				<div class="space-y-2">
					{#each Array(4) as _, i}
						<div class="flex items-center justify-between">
							<div class="h-3 bg-slate-600 rounded w-16 animate-pulse"></div>
							<div class="flex items-center gap-2">
								<div class="w-2 h-2 bg-slate-600 rounded-full animate-pulse"></div>
								<div class="h-3 bg-slate-600 rounded w-12 animate-pulse"></div>
							</div>
						</div>
					{/each}
				</div>
			{:else if $systemStatusStore.error}
				<!-- Error state -->
				<div class="flex items-center gap-2 text-threat-critical">
					<AlertTriangle class="w-3 h-3" />
					<span class="text-xs">Health check failed</span>
				</div>
			{:else if $systemStatusStore.data}
				<!-- Loaded system status -->
				<div class="space-y-2">
					<!-- API Gateway -->
					{#if $systemStatusStore.data.api_gateway}
						{@const apiGatewayStatus = getSystemStatusDisplay($systemStatusStore.data.api_gateway)}
						<div class="flex items-center justify-between">
							<span class="text-xs text-slate-400">API Gateway</span>
							<div class="flex items-center gap-2">
								<div class="w-2 h-2 {apiGatewayStatus.color} rounded-full {$systemStatusStore.data.api_gateway === 'degraded' ? 'animate-pulse' : ''}"></div>
								<span class="text-xs {apiGatewayStatus.textColor} font-medium">{apiGatewayStatus.label}</span>
							</div>
						</div>
					{/if}

					<!-- Lambda Functions -->
					{#if $systemStatusStore.data.lambda_functions}
						{@const lambdaStatus = getSystemStatusDisplay($systemStatusStore.data.lambda_functions)}
						<div class="flex items-center justify-between">
							<span class="text-xs text-slate-400">Lambda Functions</span>
							<div class="flex items-center gap-2">
								<div class="w-2 h-2 {lambdaStatus.color} rounded-full {$systemStatusStore.data.lambda_functions === 'degraded' ? 'animate-pulse' : ''}"></div>
								<span class="text-xs {lambdaStatus.textColor} font-medium">{lambdaStatus.label}</span>
							</div>
						</div>
					{/if}

					<!-- Database -->
					{#if $systemStatusStore.data.database}
						{@const databaseStatus = getSystemStatusDisplay($systemStatusStore.data.database)}
						<div class="flex items-center justify-between">
							<span class="text-xs text-slate-400">Database</span>
							<div class="flex items-center gap-2">
								<div class="w-2 h-2 {databaseStatus.color} rounded-full {$systemStatusStore.data.database === 'degraded' ? 'animate-pulse' : ''}"></div>
								<span class="text-xs {databaseStatus.textColor} font-medium">{databaseStatus.label}</span>
							</div>
						</div>
					{/if}

					<!-- Storage -->
					{#if $systemStatusStore.data.storage}
						{@const storageStatus = getSystemStatusDisplay($systemStatusStore.data.storage)}
						<div class="flex items-center justify-between">
							<span class="text-xs text-slate-400">Storage</span>
							<div class="flex items-center gap-2">
								<div class="w-2 h-2 {storageStatus.color} rounded-full {$systemStatusStore.data.storage === 'degraded' ? 'animate-pulse' : ''}"></div>
								<span class="text-xs {storageStatus.textColor} font-medium">{storageStatus.label}</span>
							</div>
						</div>
					{/if}
				</div>
			{/if}
		</div>

		<!-- Recent Threats Summary -->
		<div class="mt-4 glass-tertiary rounded-lg p-3">
			<div class="flex items-center justify-between mb-3">
				<h4 class="text-sm font-semibold text-slate-200">Recent Threats</h4>
				{#if $recentThreatsStore.loading}
					<Loader2 class="w-3 h-3 animate-spin text-slate-400" />
				{/if}
			</div>

			{#if $recentThreatsStore.loading}
				<!-- Loading state -->
				<div class="space-y-2">
					{#each Array(4) as _, i}
						<div class="flex items-center justify-between">
							<div class="h-3 bg-slate-600 rounded w-12 animate-pulse"></div>
							<div class="h-3 bg-slate-600 rounded w-6 animate-pulse"></div>
						</div>
					{/each}
				</div>
			{:else if $recentThreatsStore.error}
				<!-- Error state -->
				<div class="flex items-center gap-2 text-threat-critical">
					<AlertTriangle class="w-3 h-3" />
					<span class="text-xs">Load failed</span>
				</div>
			{:else}
				<!-- Loaded threat counts -->
				{@const threatCounts = getThreatCounts($recentThreatsStore.data)}
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<span class="text-xs text-slate-400">Critical</span>
						<span class="text-xs font-mono text-threat-critical font-bold {threatCounts.critical > 0 ? 'animate-pulse' : ''}">{threatCounts.critical}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="text-xs text-slate-400">High</span>
						<span class="text-xs font-mono text-threat-high font-bold">{threatCounts.high}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="text-xs text-slate-400">Medium</span>
						<span class="text-xs font-mono text-threat-medium font-bold">{threatCounts.medium}</span>
					</div>
					<div class="flex items-center justify-between border-t border-slate-700/30 pt-2 mt-2">
						<span class="text-xs text-slate-400 font-medium">Total Recent</span>
						<span class="text-xs font-mono text-slate-200 font-bold">{threatCounts.total}</span>
					</div>
				</div>
			{/if}
		</div>
	</div>
</aside>