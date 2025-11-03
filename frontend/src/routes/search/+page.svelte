<script lang="ts">
	import {
		Search, Filter, Download, Eye, Shield, Globe,
		Calendar, Clock, TrendingUp, AlertTriangle
	} from 'lucide-svelte';

	let searchQuery = '';
	let selectedFilter = 'all';
	let searchResults = [
		{
			id: 1,
			type: 'ip',
			value: '192.168.1.100',
			severity: 'critical',
			description: 'Known malicious IP address associated with botnet activity',
			source: 'OTX',
			lastSeen: '2 hours ago',
			confidence: 95
		},
		{
			id: 2,
			type: 'domain',
			value: 'evil-domain.com',
			severity: 'high',
			description: 'Domain hosting phishing content targeting financial institutions',
			source: 'Abuse.ch',
			lastSeen: '5 hours ago',
			confidence: 89
		},
		{
			id: 3,
			type: 'hash',
			value: 'a1b2c3d4e5f6...',
			severity: 'medium',
			description: 'Potentially unwanted program detected in multiple samples',
			source: 'OTX',
			lastSeen: '1 day ago',
			confidence: 72
		}
	];

	function getSeverityBadgeClass(severity: string) {
		switch (severity) {
			case 'critical': return 'threat-badge-critical';
			case 'high': return 'threat-badge-high';
			case 'medium': return 'threat-badge-medium';
			case 'low': return 'threat-badge-low';
			default: return 'threat-badge-unknown';
		}
	}

	function getTypeIcon(type: string) {
		switch (type) {
			case 'ip': return Globe;
			case 'domain': return Globe;
			case 'hash': return Shield;
			default: return AlertTriangle;
		}
	}
</script>

<div class="space-y-6">
	<!-- Search Header -->
	<div class="dashboard-card">
		<div class="flex items-center gap-3 mb-6">
			<Search class="w-6 h-6 text-cyber-primary" />
			<h1 class="text-2xl font-bold text-slate-100">Threat Intelligence Search</h1>
		</div>

		<!-- Search Form -->
		<div class="grid grid-cols-1 lg:grid-cols-4 gap-4">
			<!-- Search Input -->
			<div class="lg:col-span-2">
				<label for="search" class="block text-sm font-medium text-slate-300 mb-2">
					Search IOCs
				</label>
				<div class="relative">
					<Search class="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
					<input
						type="text"
						id="search"
						bind:value={searchQuery}
						placeholder="Enter IP, domain, hash, or keyword..."
						class="input-glass w-full pl-10"
					/>
				</div>
			</div>

			<!-- Filter Dropdown -->
			<div>
				<label for="filter" class="block text-sm font-medium text-slate-300 mb-2">
					IOC Type
				</label>
				<div class="relative">
					<Filter class="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-400" />
					<select
						id="filter"
						bind:value={selectedFilter}
						class="input-glass w-full pl-10 appearance-none"
					>
						<option value="all">All Types</option>
						<option value="ip">IP Address</option>
						<option value="domain">Domain</option>
						<option value="hash">File Hash</option>
						<option value="url">URL</option>
					</select>
				</div>
			</div>

			<!-- Search Button -->
			<div class="flex items-end">
				<button class="btn-primary w-full h-10">
					Search
				</button>
			</div>
		</div>
	</div>

	<!-- Search Stats -->
	<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
		<div class="dashboard-card text-center">
			<div class="text-2xl font-bold text-slate-100 font-mono">1,247</div>
			<div class="text-sm text-slate-400">Total IOCs</div>
		</div>
		<div class="dashboard-card text-center">
			<div class="text-2xl font-bold text-threat-critical font-mono">23</div>
			<div class="text-sm text-slate-400">Critical Threats</div>
		</div>
		<div class="dashboard-card text-center">
			<div class="text-2xl font-bold text-cyber-primary font-mono">0.3s</div>
			<div class="text-sm text-slate-400">Avg Query Time</div>
		</div>
		<div class="dashboard-card text-center">
			<div class="text-2xl font-bold text-threat-safe font-mono">98.5%</div>
			<div class="text-sm text-slate-400">Index Coverage</div>
		</div>
	</div>

	<!-- Search Results -->
	<div class="dashboard-card">
		<div class="flex items-center justify-between mb-6">
			<h2 class="text-lg font-semibold text-slate-100">Search Results</h2>
			<div class="flex items-center gap-3">
				<span class="text-sm text-slate-400">
					{searchResults.length} results found
				</span>
				<button class="btn-glass">
					<Download class="w-4 h-4 mr-2" />
					Export
				</button>
			</div>
		</div>

		<!-- Results Table -->
		<div class="space-y-3">
			{#each searchResults as result}
				<div class="glass-tertiary rounded-lg p-4 hover:glass-secondary transition-all duration-200">
					<div class="flex items-start justify-between">
						<div class="flex items-start gap-4 flex-1">
							<!-- IOC Icon -->
							<div class="p-2 glass-primary rounded-lg">
								<svelte:component this={getTypeIcon(result.type)} class="w-5 h-5 text-cyber-primary" />
							</div>

							<!-- IOC Details -->
							<div class="flex-1">
								<div class="flex items-center gap-3 mb-2">
									<h3 class="text-slate-100 font-mono text-sm">{result.value}</h3>
									<div class="{getSeverityBadgeClass(result.severity)}">{result.severity}</div>
									<div class="threat-badge-info">{result.type}</div>
								</div>
								<p class="text-slate-400 text-sm mb-2">{result.description}</p>
								<div class="flex items-center gap-4 text-xs text-slate-500">
									<span>Source: {result.source}</span>
									<span>Last seen: {result.lastSeen}</span>
									<span>Confidence: {result.confidence}%</span>
								</div>
							</div>
						</div>

						<!-- Actions -->
						<div class="flex items-center gap-2">
							<button class="btn-glass p-2">
								<Eye class="w-4 h-4" />
							</button>
							<button class="btn-glass p-2">
								<Globe class="w-4 h-4" />
							</button>
						</div>
					</div>

					<!-- Confidence Bar -->
					<div class="mt-3 pt-3 border-t border-slate-700/50">
						<div class="flex items-center justify-between text-xs text-slate-400 mb-1">
							<span>Confidence Score</span>
							<span>{result.confidence}%</span>
						</div>
						<div class="w-full bg-slate-800 rounded-full h-2">
							<div
								class="bg-cyber-primary h-2 rounded-full transition-all duration-300"
								style="width: {result.confidence}%"
							></div>
						</div>
					</div>
				</div>
			{/each}
		</div>

		<!-- Pagination -->
		<div class="flex items-center justify-between mt-6 pt-6 border-t border-slate-700/50">
			<div class="text-sm text-slate-400">
				Showing 1-3 of 23 results
			</div>
			<div class="flex items-center gap-2">
				<button class="btn-glass">Previous</button>
				<button class="btn-primary">1</button>
				<button class="btn-glass">2</button>
				<button class="btn-glass">3</button>
				<button class="btn-glass">Next</button>
			</div>
		</div>
	</div>
</div>