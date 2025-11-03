<script lang="ts">
  import {
    Shield, Search, Zap, BarChart3, TrendingUp, Clock,
    AlertTriangle, CheckCircle, Database, Globe,
    Eye, Activity, Server
  } from 'lucide-svelte';
  import ThreatCard from '$lib/components/ThreatCard.svelte';
  import MetricCard from '$lib/components/MetricCard.svelte';
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
        <div class="threat-badge-safe">Operational</div>
        <div class="text-slate-400 text-sm">
          Last updated: <span class="text-slate-300 font-mono">2 min ago</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Key Metrics Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <MetricCard
      title="Total Threats"
      value="1,247"
      change="+23"
      changeType="increase"
      icon={AlertTriangle}
      color="threat-critical"
    />
    <MetricCard
      title="Active Collections"
      value="5"
      change="+2"
      changeType="increase"
      icon={Zap}
      color="cyber-primary"
    />
    <MetricCard
      title="IOCs Enriched"
      value="892"
      change="+156"
      changeType="increase"
      icon={Globe}
      color="threat-info"
    />
    <MetricCard
      title="Uptime"
      value="99.97%"
      change="+0.02%"
      changeType="increase"
      icon={CheckCircle}
      color="threat-safe"
    />
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
        { label: "Collections Today", value: "24" },
        { label: "New IOCs", value: "156" },
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
        { label: "Total Records", value: "1,247" },
        { label: "Indexed IOCs", value: "2,891" },
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
        { label: "Processed", value: "892" },
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
      </div>
      <div class="space-y-4">
        <div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
          <div class="w-3 h-3 bg-threat-critical rounded-full animate-pulse"></div>
          <div class="flex-1">
            <div class="text-sm font-medium text-slate-200">Critical IOC Detected</div>
            <div class="text-xs text-slate-400 font-mono">malware.exe (SHA256: 7f9a...)</div>
          </div>
          <div class="text-xs text-slate-400">2m ago</div>
        </div>
        <div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
          <div class="w-3 h-3 bg-threat-high rounded-full"></div>
          <div class="flex-1">
            <div class="text-sm font-medium text-slate-200">Suspicious Domain Found</div>
            <div class="text-xs text-slate-400 font-mono">evil-domain.com</div>
          </div>
          <div class="text-xs text-slate-400">5m ago</div>
        </div>
        <div class="flex items-center gap-4 p-3 glass-tertiary rounded-lg">
          <div class="w-3 h-3 bg-threat-medium rounded-full"></div>
          <div class="flex-1">
            <div class="text-sm font-medium text-slate-200">IP Blacklisted</div>
            <div class="text-xs text-slate-400 font-mono">192.168.1.100</div>
          </div>
          <div class="text-xs text-slate-400">12m ago</div>
        </div>
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
      </div>
      <div class="grid grid-cols-2 gap-4">
        <!-- API Gateway -->
        <div class="glass-tertiary rounded-lg p-4 text-center">
          <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full bg-status-online/20">
            <CheckCircle class="w-6 h-6 text-status-online" />
          </div>
          <div class="text-sm font-medium text-slate-200">API Gateway</div>
          <div class="text-xs text-status-online">Online</div>
          <div class="text-xs text-slate-400 font-mono">99.9% uptime</div>
        </div>

        <!-- Lambda Functions -->
        <div class="glass-tertiary rounded-lg p-4 text-center">
          <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full bg-status-online/20">
            <Zap class="w-6 h-6 text-status-online" />
          </div>
          <div class="text-sm font-medium text-slate-200">Lambda Functions</div>
          <div class="text-xs text-status-online">Healthy</div>
          <div class="text-xs text-slate-400 font-mono">3/3 active</div>
        </div>

        <!-- Database -->
        <div class="glass-tertiary rounded-lg p-4 text-center">
          <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full bg-status-online/20">
            <Database class="w-6 h-6 text-status-online" />
          </div>
          <div class="text-sm font-medium text-slate-200">Database</div>
          <div class="text-xs text-status-online">Active</div>
          <div class="text-xs text-slate-400 font-mono">3 tables</div>
        </div>

        <!-- Storage -->
        <div class="glass-tertiary rounded-lg p-4 text-center">
          <div class="w-12 h-12 mx-auto mb-3 flex items-center justify-center rounded-full bg-status-degraded/20">
            <Eye class="w-6 h-6 text-status-degraded animate-pulse" />
          </div>
          <div class="text-sm font-medium text-slate-200">Storage</div>
          <div class="text-xs text-status-degraded">Syncing</div>
          <div class="text-xs text-slate-400 font-mono">3 buckets</div>
        </div>
      </div>
    </div>
  </div>
</div>
