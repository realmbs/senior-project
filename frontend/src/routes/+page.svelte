<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Shield, Search, Zap, BarChart3, TrendingUp, Clock,
    AlertTriangle, CheckCircle, Database, Globe,
    Eye, Activity, Server, Loader2
  } from 'lucide-svelte';
  import ThreatCard from '$lib/components/ThreatCard.svelte';
  import MetricCard from '$lib/components/MetricCard.svelte';
  import {
    dashboardStore,
    metricsStore,
    recentThreatsStore,
    systemStatusStore,
    dashboardActions
  } from '$lib/stores/dashboard';

  // Load dashboard data on component mount
  onMount(() => {
    dashboardActions.loadDashboard();
  });

  // Helper function to format numbers with commas
  function formatNumber(num: number): string {
    return new Intl.NumberFormat().format(num);
  }

  // Helper function to get severity for threat type
  function getThreatSeverity(confidence: number): 'critical' | 'high' | 'medium' | 'low' {
    if (confidence >= 90) return 'critical';
    if (confidence >= 70) return 'high';
    if (confidence >= 50) return 'medium';
    return 'low';
  }

  // Helper function to format time ago
  function timeAgo(dateString: string): string {
    const date = new Date(dateString);
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

  // Helper function to get system status color and icon
  function getSystemStatusDisplay(status: string) {
    switch (status) {
      case 'healthy':
        return {
          color: 'bg-status-online/20',
          textColor: 'text-status-online',
          icon: CheckCircle,
          label: 'Online'
        };
      case 'degraded':
        return {
          color: 'bg-status-degraded/20',
          textColor: 'text-status-degraded',
          icon: Eye,
          label: 'Degraded'
        };
      default:
        return {
          color: 'bg-status-offline/20',
          textColor: 'text-status-offline',
          icon: AlertTriangle,
          label: 'Offline'
        };
    }
  }
</script>

<div class="space-y-6">
  <!-- Dashboard Header -->
  <div class="dashboard-card">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-slate-100 mb-2">
          Threat Intelligence Dashboard
        </h1>
        <p class="text-slate-400">
          Real-time OSINT collection and threat analysis overview
        </p>
      </div>
      <div class="flex items-center gap-3">
        {#if $systemStatusStore.loading}
          <div class="flex items-center gap-2">
            <Loader2 class="w-4 h-4 animate-spin text-slate-400" />
            <span class="text-slate-400 text-sm">Checking status...</span>
          </div>
        {:else if $systemStatusStore.error}
          <div class="threat-badge-critical">System Error</div>
        {:else}
          <div class="threat-badge-safe">Operational</div>
        {/if}
        <div class="text-slate-400 text-sm">
          Last updated: <span class="text-slate-300 font-mono">
            {$dashboardStore.lastUpdated ? timeAgo($dashboardStore.lastUpdated.toISOString()) : 'Never'}
          </span>
        </div>
      </div>
    </div>
  </div>

  <!-- Key Metrics Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    {#if $metricsStore.loading}
      <!-- Loading state for metrics -->
      {#each Array(4) as _, i}
        <div class="dashboard-card">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="p-2 glass-tertiary rounded-lg">
                <Loader2 class="w-5 h-5 animate-spin text-slate-400" />
              </div>
              <div>
                <div class="h-4 bg-slate-700 rounded w-20 mb-2"></div>
                <div class="h-6 bg-slate-600 rounded w-16"></div>
              </div>
            </div>
            <div class="h-4 bg-slate-700 rounded w-12"></div>
          </div>
        </div>
      {/each}
    {:else if $metricsStore.error}
      <!-- Error state for metrics -->
      <div class="dashboard-card col-span-full">
        <div class="flex items-center gap-3 text-threat-critical">
          <AlertTriangle class="w-5 h-5" />
          <span>Failed to load metrics: {$metricsStore.error}</span>
          <button
            class="btn-glass ml-auto"
            on:click={() => dashboardActions.fetchMetrics()}
          >
            Retry
          </button>
        </div>
      </div>
    {:else}
      <!-- Loaded metrics -->
      <MetricCard
        title="Total Threats"
        value={formatNumber($metricsStore.data.totalThreats)}
        change="+{Math.floor($metricsStore.data.totalThreats * 0.02)}"
        changeType="increase"
        icon={AlertTriangle}
        color="threat-critical"
      />
      <MetricCard
        title="Active Collections"
        value={$metricsStore.data.activeCollections.toString()}
        change="+1"
        changeType="increase"
        icon={Zap}
        color="cyber-primary"
      />
      <MetricCard
        title="IOCs Enriched"
        value={formatNumber($metricsStore.data.iocsEnriched)}
        change="+{Math.floor($metricsStore.data.iocsEnriched * 0.15)}"
        changeType="increase"
        icon={Globe}
        color="threat-info"
      />
      <MetricCard
        title="Uptime"
        value="{$metricsStore.data.uptime.toFixed(2)}%"
        change="+0.02%"
        changeType="increase"
        icon={CheckCircle}
        color="threat-safe"
      />
    {/if}
  </div>

  <!-- Main Action Cards -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <!-- Threat Collection -->
    <ThreatCard
      title="Threat Collection"
      description="Automated collection from OSINT sources including OTX and Abuse.ch"
      icon={Zap}
      severity="info"
      status="active"
      actions={[
        { label: "Start Collection", type: "primary" },
        { label: "View Sources", type: "secondary" }
      ]}
      stats={[
        { label: "Collections Today", value: $metricsStore.loading ? "..." : "24" },
        { label: "New IOCs", value: $metricsStore.loading ? "..." : Math.floor($metricsStore.data.totalThreats * 0.15).toString() },
        { label: "Success Rate", value: "98.5%" }
      ]}
    />

    <!-- Search & Analysis -->
    <ThreatCard
      title="Search & Analysis"
      description="Query and analyze collected threat intelligence with advanced filtering"
      icon={Search}
      severity="low"
      status="ready"
      actions={[
        { label: "Search Threats", type: "primary" },
        { label: "Advanced Query", type: "secondary" }
      ]}
      stats={[
        { label: "Total Records", value: $metricsStore.loading ? "..." : formatNumber($metricsStore.data.totalThreats) },
        { label: "Indexed IOCs", value: $metricsStore.loading ? "..." : formatNumber($metricsStore.data.totalThreats * 2.3) },
        { label: "Avg Query Time", value: "0.3s" }
      ]}
    />

    <!-- OSINT Enrichment -->
    <ThreatCard
      title="OSINT Enrichment"
      description="Enrich IOCs with Shodan, DNS, and geolocation intelligence"
      icon={Globe}
      severity="medium"
      status="processing"
      actions={[
        { label: "Enrich IOCs", type: "primary" },
        { label: "View Queue", type: "secondary" }
      ]}
      stats={[
        { label: "Queue Size", value: "47" },
        { label: "Processed", value: $metricsStore.loading ? "..." : formatNumber($metricsStore.data.iocsEnriched) },
        { label: "Success Rate", value: "94.2%" }
      ]}
    />
  </div>

  <!-- Recent Activity & System Health -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- Recent Threat Activity -->
    <div class="dashboard-card">
      <div class="flex items-center gap-3 mb-6">
        <Activity class="w-6 h-6 text-cyber-primary" />
        <h2 class="text-lg font-semibold text-slate-100">Recent Threat Activity</h2>
        {#if $recentThreatsStore.loading}
          <Loader2 class="w-4 h-4 animate-spin text-slate-400 ml-auto" />
        {/if}
      </div>
      <div class="space-y-4">
        {#if $recentThreatsStore.loading}
          <!-- Loading state -->
          {#each Array(3) as _, i}
            <div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
              <div class="w-3 h-3 bg-slate-600 rounded-full animate-pulse"></div>
              <div class="flex-1">
                <div class="h-4 bg-slate-600 rounded w-32 mb-1"></div>
                <div class="h-3 bg-slate-700 rounded w-24"></div>
              </div>
              <div class="h-3 bg-slate-700 rounded w-12"></div>
            </div>
          {/each}
        {:else if $recentThreatsStore.error}
          <!-- Error state -->
          <div class="flex items-center gap-3 p-3 glass-tertiary rounded-lg">
            <AlertTriangle class="w-5 h-5 text-threat-critical" />
            <div class="flex-1">
              <div class="text-sm font-medium text-slate-200">Failed to load recent threats</div>
              <div class="text-xs text-slate-400">{$recentThreatsStore.error}</div>
            </div>
            <button
              class="btn-glass text-xs"
              on:click={() => dashboardActions.fetchRecentThreats()}
            >
              Retry
            </button>
          </div>
        {:else if $recentThreatsStore.data.length === 0}
          <!-- Empty state -->
          <div class="flex items-center justify-center p-8 text-slate-400">
            <div class="text-center">
              <Activity class="w-8 h-8 mx-auto mb-2 opacity-50" />
              <div class="text-sm">No recent threat activity</div>
            </div>
          </div>
        {:else}
          <!-- Loaded threats -->
          {#each $recentThreatsStore.data as threat (threat.id)}
            {@const severity = getThreatSeverity(threat.confidence)}
            {@const severityColor = severity === 'critical' ? 'bg-threat-critical' :
                                   severity === 'high' ? 'bg-threat-high' :
                                   severity === 'medium' ? 'bg-threat-medium' : 'bg-threat-low'}
            <div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
              <div class="w-3 h-3 {severityColor} rounded-full {severity === 'critical' ? 'animate-pulse' : ''}"></div>
              <div class="flex-1">
                <div class="text-sm font-medium text-slate-200">
                  {threat.type.toUpperCase()} Detected
                  {#if threat.confidence >= 90}
                    <span class="text-threat-critical text-xs">(Critical)</span>
                  {:else if threat.confidence >= 70}
                    <span class="text-threat-high text-xs">(High)</span>
                  {:else if threat.confidence >= 50}
                    <span class="text-threat-medium text-xs">(Medium)</span>
                  {:else}
                    <span class="text-threat-low text-xs">(Low)</span>
                  {/if}
                </div>
                <div class="text-xs text-slate-400 font-mono">
                  {threat.value.length > 40 ? threat.value.substring(0, 40) + '...' : threat.value}
                </div>
              </div>
              <div class="text-xs text-slate-400">{timeAgo(threat.created_at)}</div>
            </div>
          {/each}
        {/if}
      </div>
      <div class="mt-4 pt-4 border-t border-slate-700/50">
        <button class="btn-glass text-sm w-full">View All Activity</button>
      </div>
    </div>

    <!-- System Health Dashboard -->
    <div class="dashboard-card">
      <div class="flex items-center gap-3 mb-6">
        <Server class="w-6 h-6 text-cyber-primary" />
        <h2 class="text-lg font-semibold text-slate-100">System Health</h2>
        {#if $systemStatusStore.loading}
          <Loader2 class="w-4 h-4 animate-spin text-slate-400 ml-auto" />
        {/if}
      </div>

      {#if $systemStatusStore.loading}
        <!-- Loading state -->
        <div class="grid grid-cols-2 gap-4">
          {#each Array(4) as _, i}
            <div class="glass-tertiary rounded-lg p-4 text-center">
              <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full bg-slate-700">
                <Loader2 class="w-6 h-6 animate-spin text-slate-400" />
              </div>
              <div class="h-4 bg-slate-600 rounded w-20 mx-auto mb-1"></div>
              <div class="h-3 bg-slate-700 rounded w-16 mx-auto mb-1"></div>
              <div class="h-3 bg-slate-700 rounded w-12 mx-auto"></div>
            </div>
          {/each}
        </div>
      {:else if $systemStatusStore.error}
        <!-- Error state -->
        <div class="flex items-center gap-3 p-4 glass-tertiary rounded-lg">
          <AlertTriangle class="w-6 h-6 text-threat-critical" />
          <div class="flex-1">
            <div class="text-sm font-medium text-slate-200">System Health Check Failed</div>
            <div class="text-xs text-slate-400">{$systemStatusStore.error}</div>
          </div>
          <button
            class="btn-glass text-xs"
            on:click={() => dashboardActions.fetchSystemStatus()}
          >
            Retry
          </button>
        </div>
      {:else}
        <!-- Loaded system status -->
        <div class="grid grid-cols-2 gap-4">
          <!-- API Gateway -->
          <div class="glass-tertiary rounded-lg p-4 text-center">
            {#if $systemStatusStore.data}
              {@const apiGatewayStatus = getSystemStatusDisplay($systemStatusStore.data.api_gateway)}
              <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full {apiGatewayStatus.color}">
                <svelte:component this={apiGatewayStatus.icon} class="w-6 h-6 {apiGatewayStatus.textColor}" />
              </div>
              <div class="text-sm font-medium text-slate-200">API Gateway</div>
              <div class="text-xs {apiGatewayStatus.textColor}">{apiGatewayStatus.label}</div>
              <div class="text-xs text-slate-400 font-mono">99.9% uptime</div>
            {/if}
          </div>

          <!-- Lambda Functions -->
          <div class="glass-tertiary rounded-lg p-4 text-center">
            {#if $systemStatusStore.data}
              {@const lambdaStatus = getSystemStatusDisplay($systemStatusStore.data.lambda_functions)}
              <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full {lambdaStatus.color}">
                <svelte:component this={lambdaStatus.icon} class="w-6 h-6 {lambdaStatus.textColor}" />
              </div>
              <div class="text-sm font-medium text-slate-200">Lambda Functions</div>
              <div class="text-xs {lambdaStatus.textColor}">{lambdaStatus.label}</div>
              <div class="text-xs text-slate-400 font-mono">3/3 active</div>
            {/if}
          </div>

          <!-- Database -->
          <div class="glass-tertiary rounded-lg p-4 text-center">
            {#if $systemStatusStore.data}
              {@const databaseStatus = getSystemStatusDisplay($systemStatusStore.data.database)}
              <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full {databaseStatus.color}">
                <svelte:component this={databaseStatus.icon} class="w-6 h-6 {databaseStatus.textColor}" />
              </div>
              <div class="text-sm font-medium text-slate-200">Database</div>
              <div class="text-xs {databaseStatus.textColor}">{databaseStatus.label}</div>
              <div class="text-xs text-slate-400 font-mono">3 tables</div>
            {/if}
          </div>

          <!-- Storage -->
          <div class="glass-tertiary rounded-lg p-4 text-center">
            {#if $systemStatusStore.data}
              {@const storageStatus = getSystemStatusDisplay($systemStatusStore.data.storage)}
              <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full {storageStatus.color}">
                <svelte:component this={storageStatus.icon} class="w-6 h-6 {storageStatus.textColor} {$systemStatusStore.data.storage === 'degraded' ? 'animate-pulse' : ''}" />
              </div>
              <div class="text-sm font-medium text-slate-200">Storage</div>
              <div class="text-xs {storageStatus.textColor}">{storageStatus.label}</div>
              <div class="text-xs text-slate-400 font-mono">3 buckets</div>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>
