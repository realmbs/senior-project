<script lang="ts">
	import {
		Globe, Plus, Upload, Search, MapPin, Server,
		Shield, Eye, Clock, TrendingUp, Database,
		CheckCircle, AlertTriangle, RefreshCw, Loader2
	} from 'lucide-svelte';
	import { onMount } from 'svelte';
	import { enrichmentStore, enrichmentActions } from '$lib/stores/enrichment';

	let enrichmentInput = '';
	let enrichmentType = 'ip';
	let selectedServices = ['shodan', 'dns', 'geolocation'];

	// Reactive state from store
	$: isLoading = $enrichmentStore.loading.enrichment;
	$: error = $enrichmentStore.errors.enrichment;

	onMount(async () => {
		await enrichmentActions.loadStats();
	});

	async function performEnrichment() {
		if (!enrichmentInput.trim()) {
			enrichmentActions.clearError('enrichment');
			// Set a temporary error (would be better to add a validation error type)
			return;
		}

		if (selectedServices.length === 0) {
			enrichmentActions.clearError('enrichment');
			return;
		}

		try {
			await enrichmentActions.enrichIndicators([enrichmentInput.trim()], selectedServices);
			// Clear input on success
			enrichmentInput = '';
		} catch (err) {
			// Error is handled by the store
			console.error('Enrichment failed:', err);
		}
	}

	function clearError() {
		enrichmentActions.clearError('enrichment');
	}

	function timeAgo(timestamp: string): string {
		if (timestamp === 'Queued') return timestamp;

		const date = new Date(timestamp);
		const now = new Date();
		const diffMs = now.getTime() - date.getTime();
		const diffMins = Math.floor(diffMs / (1000 * 60));

		if (diffMins < 1) return 'just now';
		if (diffMins < 60) return `${diffMins}m ago`;
		const diffHours = Math.floor(diffMins / 60);
		if (diffHours < 24) return `${diffHours}h ago`;
		const diffDays = Math.floor(diffHours / 24);
		return `${diffDays}d ago`;
	}

	function getStatusIcon(status: string) {
		switch (status) {
			case 'completed': return CheckCircle;
			case 'processing': return RefreshCw;
			case 'pending': return Clock;
			case 'failed': return AlertTriangle;
			default: return Clock;
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'completed': return 'text-status-online';
			case 'processing': return 'text-cyber-primary';
			case 'pending': return 'text-slate-400';
			case 'failed': return 'text-status-offline';
			default: return 'text-slate-400';
		}
	}

	function getStatusBadge(status: string) {
		switch (status) {
			case 'completed': return 'threat-badge-safe';
			case 'processing': return 'threat-badge-medium';
			case 'pending': return 'threat-badge-info';
			case 'failed': return 'threat-badge-critical';
			default: return 'threat-badge-unknown';
		}
	}
</script>

<div class="space-y-6">
	<!-- Enrichment Header -->
	<div class="dashboard-card">
		<div class="flex items-center gap-3 mb-6">
			<Globe class="w-6 h-6 text-cyber-primary" />
			<div>
				<h1 class="text-2xl font-bold text-slate-100">OSINT Enrichment</h1>
				<p class="text-slate-400">Enhance IOCs with external intelligence sources</p>
			</div>
		</div>

		<!-- Enrichment Form -->
		<div class="grid grid-cols-1 lg:grid-cols-5 gap-4">
			<!-- IOC Type -->
			<div>
				<label class="block text-sm font-medium text-slate-300 mb-2">
					IOC Type
				</label>
				<select bind:value={enrichmentType} class="input-glass w-full">
					<option value="ip">IP Address</option>
					<option value="domain">Domain</option>
					<option value="hash">File Hash</option>
					<option value="url">URL</option>
				</select>
			</div>

			<!-- IOC Input -->
			<div class="lg:col-span-2">
				<label class="block text-sm font-medium text-slate-300 mb-2">
					Indicator of Compromise
				</label>
				<input
					type="text"
					bind:value={enrichmentInput}
					placeholder="Enter IOC to enrich..."
					class="input-glass w-full"
				/>
			</div>

			<!-- Services -->
			<div>
				<label class="block text-sm font-medium text-slate-300 mb-2">
					Services
				</label>
				<div class="text-xs text-slate-400">
					{selectedServices.length} selected
				</div>
			</div>

			<!-- Enrich Button -->
			<div class="flex items-end">
				<button
					class="btn-primary w-full h-10"
					on:click={performEnrichment}
					disabled={isLoading}
				>
					{#if isLoading}
						<Loader2 class="w-4 h-4 mr-2 animate-spin" />
						Enriching...
					{:else}
						<Plus class="w-4 h-4 mr-2" />
						Enrich
					{/if}
				</button>
			</div>
		</div>
	</div>

	<!-- Error Display -->
	{#if error}
		<div class="dashboard-card border border-threat-critical/30">
			<div class="flex items-center gap-3">
				<AlertTriangle class="w-5 h-5 text-threat-critical" />
				<div class="flex-1">
					<div class="text-threat-critical font-medium">Enrichment Error</div>
					<div class="text-slate-400 text-sm">{error}</div>
				</div>
				<button class="btn-glass" on:click={clearError}>
					Dismiss
				</button>
			</div>
		</div>
	{/if}

	<!-- Stats Loading/Error Display -->
	{#if $enrichmentStore.errors.stats}
		<div class="dashboard-card border border-threat-medium/30">
			<div class="flex items-center gap-3">
				<AlertTriangle class="w-5 h-5 text-threat-medium" />
				<div class="text-threat-medium text-sm">{$enrichmentStore.errors.stats}</div>
			</div>
		</div>
	{/if}

	<!-- Enrichment Stats -->
	<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
		{#if $enrichmentStore.loading.stats}
			<!-- Loading skeletons -->
			{#each Array(4) as _, i}
				<div class="dashboard-card text-center">
					<div class="w-6 h-6 bg-slate-600 rounded mx-auto mb-2 animate-pulse"></div>
					<div class="h-8 bg-slate-600 rounded w-16 mx-auto mb-2 animate-pulse"></div>
					<div class="h-4 bg-slate-700 rounded w-20 mx-auto animate-pulse"></div>
				</div>
			{/each}
		{:else}
			<div class="dashboard-card text-center">
				<Database class="w-6 h-6 text-cyber-primary mx-auto mb-2" />
				<div class="text-2xl font-bold text-slate-100 font-mono">{$enrichmentStore.stats.iocsEnriched.toLocaleString()}</div>
				<div class="text-sm text-slate-400">IOCs Enriched</div>
			</div>
			<div class="dashboard-card text-center">
				<Clock class="w-6 h-6 text-threat-medium mx-auto mb-2" />
				<div class="text-2xl font-bold text-slate-100 font-mono">{$enrichmentStore.stats.inQueue}</div>
				<div class="text-sm text-slate-400">In Queue</div>
			</div>
			<div class="dashboard-card text-center">
				<TrendingUp class="w-6 h-6 text-threat-safe mx-auto mb-2" />
				<div class="text-2xl font-bold text-slate-100 font-mono">{$enrichmentStore.stats.successRate.toFixed(1)}%</div>
				<div class="text-sm text-slate-400">Success Rate</div>
			</div>
			<div class="dashboard-card text-center">
				<Server class="w-6 h-6 text-threat-info mx-auto mb-2" />
				<div class="text-2xl font-bold text-slate-100 font-mono">{$enrichmentStore.stats.activeServices}</div>
				<div class="text-sm text-slate-400">Active Services</div>
			</div>
		{/if}
	</div>

	<!-- Main Content Grid -->
	<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
		<!-- Enrichment Services -->
		<div class="dashboard-card">
			<div class="flex items-center gap-3 mb-6">
				<Shield class="w-5 h-5 text-cyber-primary" />
				<h2 class="text-lg font-semibold text-slate-100">Enrichment Services</h2>
			</div>

			<div class="space-y-4">
				{#each $enrichmentStore.services as service}
					<div class="glass-tertiary rounded-lg p-4">
						<div class="flex items-start justify-between">
							<div class="flex items-start gap-3 flex-1">
								<div class="p-2 glass-primary rounded-lg">
									<Globe class="w-4 h-4 text-cyber-primary" />
								</div>
								<div class="flex-1">
									<div class="flex items-center gap-3 mb-1">
										<h3 class="text-slate-100 font-medium">{service.name}</h3>
										<div class="{service.enabled ? 'threat-badge-safe' : 'threat-badge-critical'}">
											{service.enabled ? 'Active' : 'Disabled'}
										</div>
										{#if service.status === 'degraded'}
											<div class="threat-badge-medium">Degraded</div>
										{:else if service.status === 'offline'}
											<div class="threat-badge-critical">Offline</div>
										{/if}
									</div>
									<p class="text-slate-400 text-sm mb-2">{service.description}</p>
									<div class="grid grid-cols-2 gap-2 text-xs">
										<div>
											<span class="text-slate-500">API Key:</span>
											<span class="text-slate-300 ml-1">{service.apiKey}</span>
										</div>
										<div>
											<span class="text-slate-500">Cost:</span>
											<span class="text-slate-300 ml-1">{service.cost}</span>
										</div>
									</div>
								</div>
							</div>
							<label class="flex items-center">
								<input
									type="checkbox"
									bind:group={selectedServices}
									value={service.id}
									disabled={!service.enabled}
									class="sr-only"
								/>
								<div class="{selectedServices.includes(service.id) && service.enabled ? 'bg-cyber-primary' : 'glass-tertiary'}
								     w-10 h-6 rounded-full p-1 transition-all duration-200">
									<div class="{selectedServices.includes(service.id) && service.enabled ? 'translate-x-4' : 'translate-x-0'}
									     bg-white w-4 h-4 rounded-full transition-transform duration-200"></div>
								</div>
							</label>
						</div>
					</div>
				{/each}
			</div>
		</div>

		<!-- Enrichment Queue -->
		<div class="dashboard-card">
			<div class="flex items-center justify-between mb-6">
				<div class="flex items-center gap-3">
					<Clock class="w-5 h-5 text-cyber-primary" />
					<h2 class="text-lg font-semibold text-slate-100">Enrichment Queue</h2>
				</div>
				<button class="btn-glass">
					<Upload class="w-4 h-4 mr-2" />
					Bulk Upload
				</button>
			</div>

			<div class="space-y-3">
				{#if $enrichmentStore.queue.length === 0}
					<div class="text-center p-8 text-slate-400">
						<Clock class="w-8 h-8 mx-auto mb-2 opacity-50" />
						<div class="text-sm">No items in enrichment queue</div>
					</div>
				{:else}
					{#each $enrichmentStore.queue as item}
						<div class="glass-tertiary rounded-lg p-4">
							<div class="flex items-start justify-between mb-3">
								<div class="flex items-start gap-3 flex-1">
									<div class="p-2 glass-primary rounded-lg">
										<svelte:component this={getStatusIcon(item.status)}
											class="w-4 h-4 {getStatusColor(item.status)} {item.status === 'processing' ? 'animate-spin' : ''}" />
									</div>
									<div class="flex-1">
										<div class="flex items-center gap-3 mb-1">
											<span class="text-slate-100 font-mono text-sm">
												{item.indicator.length > 30 ? item.indicator.substring(0, 30) + '...' : item.indicator}
											</span>
											<div class="{getStatusBadge(item.status)}">{item.status}</div>
										</div>
										<div class="text-xs text-slate-400 mb-2">
											Services: {item.services.join(', ')}
										</div>
										<div class="text-xs text-slate-500">
											Started: {timeAgo(item.startTime)}
										</div>
									</div>
								</div>
								<button class="btn-glass p-1">
									<Eye class="w-4 h-4" />
								</button>
							</div>

							<!-- Progress Bar -->
							{#if item.status === 'processing' || item.status === 'completed'}
								<div class="mt-3 pt-3 border-t border-slate-700/50">
									<div class="flex items-center justify-between text-xs text-slate-400 mb-1">
										<span>Progress</span>
										<span>{item.progress}%</span>
									</div>
									<div class="w-full bg-slate-800 rounded-full h-2">
										<div
											class="bg-cyber-primary h-2 rounded-full transition-all duration-300 {item.status === 'processing' ? 'animate-pulse' : ''}"
											style="width: {item.progress}%"
										></div>
									</div>
								</div>
							{/if}
						</div>
					{/each}
				{/if}
			</div>

			<div class="mt-4 pt-4 border-t border-slate-700/50">
				<button class="btn-glass text-sm w-full">View All Queue Items</button>
			</div>
		</div>
	</div>

	<!-- Recent Enrichment Results -->
	<div class="dashboard-card">
		<div class="flex items-center gap-3 mb-6">
			<Search class="w-5 h-5 text-cyber-primary" />
			<h2 class="text-lg font-semibold text-slate-100">Recent Enrichment Results</h2>
		</div>

		<div class="space-y-3">
			{#if $enrichmentStore.recentResults.length === 0}
				<div class="text-center p-8 text-slate-400">
					<Search class="w-8 h-8 mx-auto mb-2 opacity-50" />
					<div class="text-sm">No recent enrichment results</div>
				</div>
			{:else}
				{#each $enrichmentStore.recentResults as result}
					<div class="glass-tertiary rounded-lg p-4">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-4">
								<div class="p-2 glass-primary rounded-lg">
									<MapPin class="w-4 h-4 text-cyber-primary" />
								</div>
								<div>
									<div class="text-slate-100 font-mono text-sm">
										{result.indicator.length > 25 ? result.indicator.substring(0, 25) + '...' : result.indicator}
									</div>
									<div class="text-xs text-slate-400">
										Enriched with {result.services.join(', ')} (confidence: {result.confidence}%)
									</div>
								</div>
							</div>
							<div class="flex items-center gap-3">
								<div class="text-xs text-slate-400">{timeAgo(result.timestamp)}</div>
								<button class="btn-glass p-1">
									<Eye class="w-4 h-4" />
								</button>
							</div>
						</div>
					</div>
				{/each}
			{/if}
		</div>

		<div class="mt-4 pt-4 border-t border-slate-700/50">
			<button class="btn-glass text-sm w-full">View All Results</button>
		</div>
	</div>
</div>