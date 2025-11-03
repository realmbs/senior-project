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
		ChevronRight
	} from 'lucide-svelte';

	// Current route - this would normally come from SvelteKit's page store
	let currentRoute = '/';

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
			<h4 class="text-sm font-semibold text-slate-200 mb-3">System Health</h4>
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">API Gateway</span>
					<div class="flex items-center gap-2">
						<div class="w-2 h-2 bg-status-online rounded-full"></div>
						<span class="text-xs text-status-online font-medium">Online</span>
					</div>
				</div>
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">Lambda Functions</span>
					<div class="flex items-center gap-2">
						<div class="w-2 h-2 bg-status-online rounded-full"></div>
						<span class="text-xs text-status-online font-medium">Healthy</span>
					</div>
				</div>
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">Database</span>
					<div class="flex items-center gap-2">
						<div class="w-2 h-2 bg-status-online rounded-full"></div>
						<span class="text-xs text-status-online font-medium">Active</span>
					</div>
				</div>
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">Storage</span>
					<div class="flex items-center gap-2">
						<div class="w-2 h-2 bg-status-degraded rounded-full animate pulse"></div>
						<span class="text-xs text-status-degraded font-medium">Sync</span>
					</div>
				</div>
			</div>
		</div>

		<!-- Recent Threats Summary -->
		<div class="mt-4 glass-tertiary rounded-lg p-3">
			<h4 class="text-sm font-semibold text-slate-200 mb-3">Recent Threats</h4>
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">Critical</span>
					<span class="text-xs font-mono text-threat-critical font-bold">3</span>
				</div>
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">High</span>
					<span class="text-xs font-mono text-threat-high font-bold">12</span>
				</div>
				<div class="flex items-center justify-between">
					<span class="text-xs text-slate-400">Medium</span>
					<span class="text-xs font-mono text-threat-medium font-bold">47</span>
				</div>
				<div class="flex items-center justify-between border-t border-slate-700/30 pt-2 mt-2">
					<span class="text-xs text-slate-400 font-medium">Total Today</span>
					<span class="text-xs font-mono text-slate-200 font-bold">62</span>
				</div>
			</div>
		</div>
	</div>
</aside>