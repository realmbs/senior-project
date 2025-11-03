<script lang="ts">
	import {
		Zap, Play, Pause, Settings, Calendar, Clock,
		Database, Shield, Globe, TrendingUp, Activity,
		CheckCircle, AlertCircle, RefreshCw
	} from 'lucide-svelte';

	let isCollecting = false;
	let selectedSources = ['otx', 'abuse_ch'];
	let collectionInterval = 'hourly';

	const sources = [
		{
			id: 'otx',
			name: 'AT&T Alien Labs OTX',
			description: 'Open Threat Exchange - Community threat intelligence',
			status: 'active',
			lastCollection: '15 minutes ago',
			iocsCollected: 1205,
			enabled: true
		},
		{
			id: 'abuse_ch',
			name: 'Abuse.ch',
			description: 'Malware and botnet intelligence feeds',
			status: 'active',
			lastCollection: '22 minutes ago',
			iocsCollected: 342,
			enabled: true
		},
		{
			id: 'misp',
			name: 'MISP Community',
			description: 'Malware Information Sharing Platform',
			status: 'inactive',
			lastCollection: 'Never',
			iocsCollected: 0,
			enabled: false
		}
	];

	function toggleCollection() {
		isCollecting = !isCollecting;
	}

	function getStatusIcon(status: string) {
		switch (status) {
			case 'active': return CheckCircle;
			case 'inactive': return AlertCircle;
			default: return RefreshCw;
		}
	}

	function getStatusColor(status: string) {
		switch (status) {
			case 'active': return 'text-status-online';
			case 'inactive': return 'text-status-offline';
			default: return 'text-slate-400';
		}
	}
</script>

<div class="space-y-6">
	<!-- Collection Header -->
	<div class="dashboard-card">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-3">
				<Zap class="w-6 h-6 text-cyber-primary" />
				<div>
					<h1 class="text-2xl font-bold text-slate-100">Threat Collection</h1>
					<p class="text-slate-400">Automated OSINT threat intelligence collection</p>
				</div>
			</div>
			<div class="flex items-center gap-3">
				<div class="text-right">
					<div class="text-sm text-slate-400">Status</div>
					<div class="{isCollecting ? 'threat-badge-safe' : 'threat-badge-medium'}">
						{isCollecting ? 'Collecting' : 'Idle'}
					</div>
				</div>
				<button
					class="{isCollecting ? 'btn-glass' : 'btn-primary'}"
					onclick={toggleCollection}
				>
					{#if isCollecting}
						<Pause class="w-4 h-4 mr-2" />
						Stop Collection
					{:else}
						<Play class="w-4 h-4 mr-2" />
						Start Collection
					{/if}
				</button>
			</div>
		</div>
	</div>

	<!-- Collection Stats -->
	<div class="grid grid-cols-1 md:grid-cols-4 gap-4">
		<div class="dashboard-card text-center">
			<Activity class="w-6 h-6 text-cyber-primary mx-auto mb-2" />
			<div class="text-2xl font-bold text-slate-100 font-mono">24</div>
			<div class="text-sm text-slate-400">Collections Today</div>
		</div>
		<div class="dashboard-card text-center">
			<Database class="w-6 h-6 text-threat-info mx-auto mb-2" />
			<div class="text-2xl font-bold text-slate-100 font-mono">1,547</div>
			<div class="text-sm text-slate-400">New IOCs</div>
		</div>
		<div class="dashboard-card text-center">
			<TrendingUp class="w-6 h-6 text-threat-safe mx-auto mb-2" />
			<div class="text-2xl font-bold text-slate-100 font-mono">98.5%</div>
			<div class="text-sm text-slate-400">Success Rate</div>
		</div>
		<div class="dashboard-card text-center">
			<Clock class="w-6 h-6 text-threat-medium mx-auto mb-2" />
			<div class="text-2xl font-bold text-slate-100 font-mono">2.3s</div>
			<div class="text-sm text-slate-400">Avg Collection Time</div>
		</div>
	</div>

	<!-- Collection Configuration -->
	<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
		<!-- Collection Settings -->
		<div class="dashboard-card lg:col-span-1">
			<div class="flex items-center gap-3 mb-6">
				<Settings class="w-5 h-5 text-cyber-primary" />
				<h2 class="text-lg font-semibold text-slate-100">Collection Settings</h2>
			</div>

			<div class="space-y-4">
				<!-- Collection Interval -->
				<div>
					<label class="block text-sm font-medium text-slate-300 mb-2">
						Collection Interval
					</label>
					<select bind:value={collectionInterval} class="input-glass w-full">
						<option value="manual">Manual</option>
						<option value="hourly">Every Hour</option>
						<option value="6hours">Every 6 Hours</option>
						<option value="daily">Daily</option>
					</select>
				</div>

				<!-- IOC Types -->
				<div>
					<label class="block text-sm font-medium text-slate-300 mb-2">
						IOC Types to Collect
					</label>
					<div class="space-y-2">
						{#each ['IP Addresses', 'Domains', 'File Hashes', 'URLs'] as iocType}
							<label class="flex items-center">
								<input type="checkbox" checked class="sr-only" />
								<div class="glass-tertiary rounded p-2 w-full text-sm text-slate-200 border border-cyber-primary/30">
									{iocType}
								</div>
							</label>
						{/each}
					</div>
				</div>

				<!-- Confidence Threshold -->
				<div>
					<label class="block text-sm font-medium text-slate-300 mb-2">
						Minimum Confidence Score
					</label>
					<input
						type="range"
						min="0"
						max="100"
						value="70"
						class="w-full"
					/>
					<div class="flex justify-between text-xs text-slate-400 mt-1">
						<span>0%</span>
						<span>70%</span>
						<span>100%</span>
					</div>
				</div>
			</div>
		</div>

		<!-- Data Sources -->
		<div class="dashboard-card lg:col-span-2">
			<div class="flex items-center gap-3 mb-6">
				<Globe class="w-5 h-5 text-cyber-primary" />
				<h2 class="text-lg font-semibold text-slate-100">Data Sources</h2>
			</div>

			<div class="space-y-4">
				{#each sources as source}
					<div class="glass-tertiary rounded-lg p-4">
						<div class="flex items-start justify-between">
							<div class="flex items-start gap-4 flex-1">
								<!-- Source Status -->
								<div class="p-2 glass-primary rounded-lg">
									<svelte:component
										this={getStatusIcon(source.status)}
										class="w-5 h-5 {getStatusColor(source.status)}"
									/>
								</div>

								<!-- Source Details -->
								<div class="flex-1">
									<div class="flex items-center gap-3 mb-2">
										<h3 class="text-slate-100 font-medium">{source.name}</h3>
										<div class="{source.status === 'active' ? 'threat-badge-safe' : 'threat-badge-critical'}">
											{source.status}
										</div>
									</div>
									<p class="text-slate-400 text-sm mb-3">{source.description}</p>
									<div class="grid grid-cols-2 gap-4 text-xs">
										<div>
											<span class="text-slate-500">Last Collection:</span>
											<span class="text-slate-300 font-mono ml-1">{source.lastCollection}</span>
										</div>
										<div>
											<span class="text-slate-500">IOCs Collected:</span>
											<span class="text-slate-300 font-mono ml-1">{source.iocsCollected.toLocaleString()}</span>
										</div>
									</div>
								</div>
							</div>

							<!-- Source Actions -->
							<div class="flex items-center gap-2">
								<button class="btn-glass p-2">
									<Settings class="w-4 h-4" />
								</button>
								<button class="{source.enabled ? 'btn-primary' : 'btn-glass'} px-3 py-1 text-sm">
									{source.enabled ? 'Enabled' : 'Enable'}
								</button>
							</div>
						</div>

						<!-- Collection Progress (if active) -->
						{#if source.status === 'active' && isCollecting}
							<div class="mt-4 pt-4 border-t border-slate-700/50">
								<div class="flex items-center justify-between text-xs text-slate-400 mb-2">
									<span>Collection Progress</span>
									<span>78%</span>
								</div>
								<div class="w-full bg-slate-800 rounded-full h-2">
									<div class="bg-cyber-primary h-2 rounded-full animate-pulse" style="width: 78%"></div>
								</div>
							</div>
						{/if}
					</div>
				{/each}
			</div>
		</div>
	</div>

	<!-- Recent Collection Activity -->
	<div class="dashboard-card">
		<div class="flex items-center gap-3 mb-6">
			<Activity class="w-5 h-5 text-cyber-primary" />
			<h2 class="text-lg font-semibold text-slate-100">Recent Collection Activity</h2>
		</div>

		<div class="space-y-3">
			{#each Array(5) as _, i}
				<div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
					<div class="w-3 h-3 bg-status-online rounded-full animate-pulse"></div>
					<div class="flex-1">
						<div class="text-sm font-medium text-slate-200">
							Collection completed from {i % 2 === 0 ? 'OTX' : 'Abuse.ch'}
						</div>
						<div class="text-xs text-slate-400">
							{Math.floor(Math.random() * 200) + 50} new IOCs collected
						</div>
					</div>
					<div class="text-xs text-slate-400">{i + 5} minutes ago</div>
				</div>
			{/each}
		</div>

		<div class="mt-4 pt-4 border-t border-slate-700/50">
			<button class="btn-glass text-sm w-full">View Full Collection Log</button>
		</div>
	</div>
</div>