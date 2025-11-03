<script lang="ts">
	import { Shield, Bell, Settings, User, Activity, Menu } from 'lucide-svelte';

	let sidebarOpen = $state(false);

	function toggleSidebar() {
		sidebarOpen = !sidebarOpen;
		// Toggle sidebar visibility on mobile
		const sidebar = document.querySelector('.sidebar');
		if (sidebar) {
			sidebar.classList.toggle('mobile-open');
		}
	}
</script>

<nav class="navbar">
	<!-- Mobile Menu Button & Logo -->
	<div class="flex items-center gap-3">
		<!-- Mobile Menu Button -->
		<button class="btn-glass p-2 lg:hidden" onclick={toggleSidebar}>
			<Menu class="w-5 h-5" />
		</button>
		<div class="flex items-center gap-2">
			<Shield class="w-8 h-8 text-cyber-primary animate-pulse-glow" />
			<div>
				<h1 class="text-xl font-bold text-slate-100">ThreatIntel</h1>
				<div class="text-xs text-slate-400 font-mono">v1.0.0</div>
			</div>
		</div>
	</div>

	<!-- Status Indicators -->
	<div class="flex items-center gap-4">
		<!-- API Status -->
		<div class="flex items-center gap-2">
			<div class="w-2 h-2 bg-status-online rounded-full animate-pulse"></div>
			<span class="text-sm text-slate-300">API Online</span>
		</div>

		<!-- System Status -->
		<div class="flex items-center gap-2">
			<Activity class="w-4 h-4 text-status-online" />
			<span class="text-sm text-slate-300">All Systems</span>
		</div>
	</div>

	<!-- User Actions -->
	<div class="flex items-center gap-3">
		<!-- Notifications -->
		<button class="btn-glass p-2 relative">
			<Bell class="w-5 h-5" />
			<div class="absolute -top-1 -right-1 w-3 h-3 bg-threat-high rounded-full"></div>
		</button>

		<!-- Settings -->
		<button class="btn-glass p-2">
			<Settings class="w-5 h-5" />
		</button>

		<!-- User Profile -->
		<button class="btn-glass p-2">
			<User class="w-5 h-5" />
		</button>
	</div>
</nav>