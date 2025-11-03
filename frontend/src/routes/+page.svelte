<script lang="ts">
  import { Shield, Search, Zap, BarChart3 } from 'lucide-svelte';
</script>

<div class="min-h-screen bg-gray-50 dark:bg-gray-900">
  <div class="container mx-auto px-4 py-8">
    <!-- Header -->
    <header class="mb-8">
      <div class="flex items-center gap-3 mb-4">
        <Shield class="w-8 h-8 text-blue-600" />
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
          Threat Intelligence Platform
        </h1>
      </div>
      <p class="text-gray-600 dark:text-gray-300">
        Automated OSINT collection and threat analysis for small businesses
      </p>
    </header>

    <!-- Dashboard Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <!-- Threat Collection Card -->
      <div class="threat-card">
        <div class="flex items-center gap-3 mb-4">
          <Zap class="w-6 h-6 text-yellow-600" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
            Threat Collection
          </h2>
        </div>
        <p class="text-gray-600 dark:text-gray-300 mb-4">
          Automated collection from OSINT sources
        </p>
        <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors">
          Start Collection
        </button>
      </div>

      <!-- Search & Analysis Card -->
      <div class="threat-card">
        <div class="flex items-center gap-3 mb-4">
          <Search class="w-6 h-6 text-green-600" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
            Search & Analysis
          </h2>
        </div>
        <p class="text-gray-600 dark:text-gray-300 mb-4">
          Query and analyze threat intelligence
        </p>
        <button class="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-lg transition-colors">
          Search Threats
        </button>
      </div>

      <!-- OSINT Enrichment Card -->
      <div class="threat-card">
        <div class="flex items-center gap-3 mb-4">
          <BarChart3 class="w-6 h-6 text-purple-600" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
            OSINT Enrichment
          </h2>
        </div>
        <p class="text-gray-600 dark:text-gray-300 mb-4">
          Enrich IOCs with external intelligence
        </p>
        <button class="w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-colors">
          Enrich Data
        </button>
      </div>
    </div>

    <!-- Status Section -->
    <div class="threat-card">
      <h2 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
        System Status
      </h2>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div class="text-center">
          <div class="text-2xl font-bold text-green-600">✓</div>
          <div class="text-sm text-gray-600 dark:text-gray-300">API Gateway</div>
        </div>
        <div class="text-center">
          <div class="text-2xl font-bold text-green-600">✓</div>
          <div class="text-sm text-gray-600 dark:text-gray-300">Lambda Functions</div>
        </div>
        <div class="text-center">
          <div class="text-2xl font-bold text-green-600">✓</div>
          <div class="text-sm text-gray-600 dark:text-gray-300">Database</div>
        </div>
        <div class="text-center">
          <div class="text-2xl font-bold text-green-600">✓</div>
          <div class="text-sm text-gray-600 dark:text-gray-300">Storage</div>
        </div>
      </div>
    </div>
  </div>
</div>
