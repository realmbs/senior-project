import './style.css'

// API Configuration
const API_CONFIG = {
  baseUrl: 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev',
  apiKey: 'mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf'
};

// TypeScript interfaces for API responses
interface ThreatIndicator {
  ioc_value: string;
  ioc_type: string;
  confidence: number;
  pulse_name: string;
  created_at: string;
  source: string;
}

interface SearchResponse {
  results: {
    results: ThreatIndicator[];
    count: number;
    search_method: string;
  };
  status: string;
}

interface DashboardMetrics {
  totalThreats: number;
  highRiskThreats: number;
  recentActivity: number;
  topSources: string[];
}

class ThreatIntelligenceDashboard {
  private metricsData: DashboardMetrics = {
    totalThreats: 0,
    highRiskThreats: 0,
    recentActivity: 0,
    topSources: []
  };

  private recentThreats: ThreatIndicator[] = [];
  private isLoading = false;

  constructor() {
    this.init();
  }

  private async init(): Promise<void> {
    console.log('🛡️ Initializing Threat Intelligence Dashboard...');

    this.renderLayout();
    this.setupEventListeners();

    // Load initial data
    await this.loadDashboardData();

    // Set up auto-refresh every 5 minutes
    setInterval(() => this.loadDashboardData(), 5 * 60 * 1000);

    console.log('✅ Dashboard initialized successfully');
  }

  private renderLayout(): void {
    const app = document.querySelector('#app');
    if (!app) return;

    app.innerHTML = `
      <div class="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 text-white">
        <!-- Header -->
        <header class="bg-gray-800/50 backdrop-blur-lg border-b border-gray-700/50">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
              <div class="flex items-center space-x-3">
                <div class="p-2 bg-blue-600 rounded-lg">
                  <i data-lucide="shield-check" class="w-6 h-6"></i>
                </div>
                <div>
                  <h1 class="text-xl font-bold">Threat Intelligence Platform</h1>
                  <p class="text-sm text-gray-400">Real-time OSINT Analysis</p>
                </div>
              </div>
              <div class="flex items-center space-x-4">
                <div id="api-status" class="flex items-center space-x-2 text-sm">
                  <div class="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
                  <span class="text-gray-300">Connecting...</span>
                </div>
                <button id="refresh-btn" class="p-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                  <i data-lucide="refresh-cw" class="w-4 h-4"></i>
                </button>
              </div>
            </div>
          </div>
        </header>

        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <!-- Metrics Overview -->
          <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-gray-400 text-sm">Total Threats</p>
                  <p id="total-threats" class="text-2xl font-bold text-white">Loading...</p>
                </div>
                <div class="p-3 bg-red-500/20 rounded-lg">
                  <i data-lucide="alert-triangle" class="w-6 h-6 text-red-400"></i>
                </div>
              </div>
            </div>

            <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-gray-400 text-sm">High Risk</p>
                  <p id="high-risk" class="text-2xl font-bold text-white">Loading...</p>
                </div>
                <div class="p-3 bg-red-500/20 rounded-lg">
                  <i data-lucide="shield-alert" class="w-6 h-6 text-red-400"></i>
                </div>
              </div>
            </div>

            <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-gray-400 text-sm">Recent Activity</p>
                  <p id="recent-activity" class="text-2xl font-bold text-white">Loading...</p>
                </div>
                <div class="p-3 bg-yellow-500/20 rounded-lg">
                  <i data-lucide="activity" class="w-6 h-6 text-yellow-400"></i>
                </div>
              </div>
            </div>

            <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6">
              <div class="flex items-center justify-between">
                <div>
                  <p class="text-gray-400 text-sm">Data Sources</p>
                  <p id="data-sources" class="text-2xl font-bold text-white">Loading...</p>
                </div>
                <div class="p-3 bg-blue-500/20 rounded-lg">
                  <i data-lucide="database" class="w-6 h-6 text-blue-400"></i>
                </div>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <!-- Recent Threats Feed -->
            <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50">
              <div class="p-6 border-b border-gray-700/50">
                <div class="flex items-center justify-between">
                  <h2 class="text-lg font-semibold flex items-center space-x-2">
                    <i data-lucide="list" class="w-5 h-5"></i>
                    <span>Recent Threats</span>
                  </h2>
                  <span id="threats-count" class="text-sm text-gray-400">0 items</span>
                </div>
              </div>
              <div id="threats-list" class="p-6 space-y-4 max-h-96 overflow-y-auto">
                <div class="flex items-center justify-center py-8">
                  <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400"></div>
                </div>
              </div>
            </div>

            <!-- Quick Actions & IOC Lookup -->
            <div class="space-y-6">
              <!-- IOC Enrichment -->
              <div class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50">
                <div class="p-6 border-b border-gray-700/50">
                  <h2 class="text-lg font-semibold flex items-center space-x-2">
                    <i data-lucide="search" class="w-5 h-5"></i>
                    <span>IOC Lookup</span>
                  </h2>
                </div>
                <div class="p-6">
                  <div class="space-y-4">
                    <div>
                      <input
                        type="text"
                        id="ioc-input"
                        placeholder="Enter IP, domain, or hash..."
                        class="w-full px-3 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <button
                      id="search-btn"
                      class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2"
                    >
                      <i data-lucide="search" class="w-4 h-4"></i>
                      <span>Search Threats</span>
                    </button>
                  </div>
                  <div id="search-results" class="mt-6 space-y-4">
                    <!-- Search results will appear here -->
                  </div>
                </div>
              </div>

              <!-- Quick Actions -->
              <div class="grid grid-cols-1 gap-4">
                <a href="/api-test.html" class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-blue-500/50 transition-colors group block">
                  <div class="flex items-center space-x-3">
                    <div class="p-2 bg-green-500/20 rounded-lg group-hover:bg-green-500/30 transition-colors">
                      <i data-lucide="settings" class="w-5 h-5 text-green-400"></i>
                    </div>
                    <div>
                      <h3 class="font-medium">API Testing</h3>
                      <p class="text-sm text-gray-400">Test API endpoints</p>
                    </div>
                  </div>
                </a>

                <button id="collect-btn" class="bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-purple-500/50 transition-colors group w-full text-left">
                  <div class="flex items-center space-x-3">
                    <div class="p-2 bg-purple-500/20 rounded-lg group-hover:bg-purple-500/30 transition-colors">
                      <i data-lucide="download-cloud" class="w-5 h-5 text-purple-400"></i>
                    </div>
                    <div>
                      <h3 class="font-medium">Trigger Collection</h3>
                      <p class="text-sm text-gray-400">Collect new threat data</p>
                    </div>
                  </div>
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    `;

    // Initialize Lucide icons after DOM is ready
    setTimeout(() => {
      if (window.lucide) {
        window.lucide.createIcons();
      }
    }, 100);
  }

  private setupEventListeners(): void {
    // Refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    refreshBtn?.addEventListener('click', () => this.loadDashboardData());

    // Search functionality
    const searchBtn = document.getElementById('search-btn');
    const iocInput = document.getElementById('ioc-input') as HTMLInputElement;

    searchBtn?.addEventListener('click', () => this.handleSearch());
    iocInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.handleSearch();
      }
    });

    // Collection trigger
    const collectBtn = document.getElementById('collect-btn');
    collectBtn?.addEventListener('click', () => this.triggerCollection());
  }

  private async loadDashboardData(): Promise<void> {
    if (this.isLoading) return;
    this.isLoading = true;

    try {
      // Update API status
      this.updateApiStatus('connecting');

      // Load recent threats (last 50)
      const response = await this.apiCall('/search?limit=50');

      if (response.ok) {
        const data: SearchResponse = await response.json();
        this.recentThreats = data.results.results || [];

        // Calculate metrics
        this.calculateMetrics();

        // Update UI
        this.updateMetricsDisplay();
        this.updateThreatsDisplay();
        this.updateApiStatus('connected');
      } else {
        throw new Error(`API Error: ${response.status}`);
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      this.updateApiStatus('error');
      this.showNotification('Failed to load dashboard data', 'error');
    } finally {
      this.isLoading = false;
    }
  }

  private calculateMetrics(): void {
    const threats = this.recentThreats;

    this.metricsData = {
      totalThreats: threats.length,
      highRiskThreats: threats.filter(t => t.confidence >= 80).length,
      recentActivity: threats.filter(t => {
        const created = new Date(t.created_at);
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        return created > yesterday;
      }).length,
      topSources: [...new Set(threats.map(t => t.source))].slice(0, 3)
    };
  }

  private updateMetricsDisplay(): void {
    const elements = {
      totalThreats: document.getElementById('total-threats'),
      highRisk: document.getElementById('high-risk'),
      recentActivity: document.getElementById('recent-activity'),
      dataSources: document.getElementById('data-sources')
    };

    if (elements.totalThreats) elements.totalThreats.textContent = this.metricsData.totalThreats.toString();
    if (elements.highRisk) elements.highRisk.textContent = this.metricsData.highRiskThreats.toString();
    if (elements.recentActivity) elements.recentActivity.textContent = this.metricsData.recentActivity.toString();
    if (elements.dataSources) elements.dataSources.textContent = this.metricsData.topSources.length.toString();
  }

  private updateThreatsDisplay(): void {
    const container = document.getElementById('threats-list');
    const countElement = document.getElementById('threats-count');

    if (!container || !countElement) return;

    countElement.textContent = `${this.recentThreats.length} items`;

    if (this.recentThreats.length === 0) {
      container.innerHTML = `
        <div class="text-center py-8 text-gray-400">
          <i data-lucide="inbox" class="w-12 h-12 mx-auto mb-4 opacity-50"></i>
          <p>No threats found</p>
        </div>
      `;
      return;
    }

    container.innerHTML = this.recentThreats.slice(0, 10).map(threat => `
      <div class="bg-gray-700/30 rounded-lg p-4 border border-gray-600/30 hover:border-gray-500/50 transition-colors">
        <div class="flex items-start justify-between">
          <div class="flex-1">
            <div class="flex items-center space-x-2 mb-2">
              <span class="px-2 py-1 bg-${this.getThreatColor(threat.confidence)}-500/20 text-${this.getThreatColor(threat.confidence)}-400 text-xs rounded-full">
                ${threat.ioc_type.toUpperCase()}
              </span>
              <span class="text-xs text-gray-400">${threat.confidence}% confidence</span>
            </div>
            <p class="text-white font-mono text-sm break-all">${threat.ioc_value}</p>
            <p class="text-gray-400 text-sm mt-1">${threat.pulse_name || threat.source || 'Unknown Source'}</p>
          </div>
          <button class="search-threat-btn text-gray-400 hover:text-blue-400 transition-colors" data-ioc="${threat.ioc_value}">
            <i data-lucide="external-link" class="w-4 h-4"></i>
          </button>
        </div>
      </div>
    `).join('');

    // Add event listeners for search buttons
    container.querySelectorAll('.search-threat-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget as HTMLElement;
        const ioc = target.dataset.ioc;
        if (ioc) {
          const input = document.getElementById('ioc-input') as HTMLInputElement;
          input.value = ioc;
          this.handleSearch();
        }
      });
    });

    // Refresh Lucide icons
    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  private async handleSearch(): Promise<void> {
    const input = document.getElementById('ioc-input') as HTMLInputElement;
    const resultsContainer = document.getElementById('search-results');
    const searchBtn = document.getElementById('search-btn');

    if (!input || !resultsContainer || !searchBtn) return;

    const query = input.value.trim();
    if (!query) {
      this.showNotification('Please enter an IOC to search', 'warning');
      return;
    }

    // Show loading state
    searchBtn.innerHTML = `
      <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
      <span>Searching...</span>
    `;

    try {
      const response = await this.apiCall(`/search?query=${encodeURIComponent(query)}&limit=10`);

      if (response.ok) {
        const data: SearchResponse = await response.json();
        this.displaySearchResults(data.results.results, resultsContainer);
      } else {
        throw new Error(`Search failed: ${response.status}`);
      }
    } catch (error) {
      console.error('Search failed:', error);
      this.showNotification('Search failed', 'error');
      resultsContainer.innerHTML = '<p class="text-gray-400">Search failed. Please try again.</p>';
    } finally {
      // Reset button
      searchBtn.innerHTML = `
        <i data-lucide="search" class="w-4 h-4"></i>
        <span>Search Threats</span>
      `;
      if (window.lucide) {
        window.lucide.createIcons();
      }
    }
  }

  private displaySearchResults(results: ThreatIndicator[], container: HTMLElement): void {
    if (results.length === 0) {
      container.innerHTML = '<p class="text-gray-400">No threats found for this query.</p>';
      return;
    }

    container.innerHTML = `
      <div class="space-y-3">
        <h4 class="text-sm font-medium text-gray-300">Search Results (${results.length})</h4>
        ${results.map(threat => `
          <div class="bg-gray-700/20 rounded-lg p-3 border border-gray-600/20">
            <div class="flex items-center space-x-2 mb-1">
              <span class="px-2 py-1 bg-${this.getThreatColor(threat.confidence)}-500/20 text-${this.getThreatColor(threat.confidence)}-400 text-xs rounded">
                ${threat.ioc_type.toUpperCase()}
              </span>
              <span class="text-xs text-gray-400">${threat.confidence}% confidence</span>
            </div>
            <p class="text-white font-mono text-sm break-all">${threat.ioc_value}</p>
            <p class="text-gray-400 text-xs mt-1">${threat.pulse_name || threat.source || 'Unknown Source'}</p>
          </div>
        `).join('')}
      </div>
    `;
  }

  private async triggerCollection(): Promise<void> {
    const collectBtn = document.getElementById('collect-btn');
    if (!collectBtn) return;

    const originalContent = collectBtn.innerHTML;
    collectBtn.innerHTML = `
      <div class="flex items-center space-x-3">
        <div class="p-2 bg-purple-500/20 rounded-lg">
          <div class="animate-spin rounded-full h-5 w-5 border-b-2 border-purple-400"></div>
        </div>
        <div>
          <h3 class="font-medium">Collecting...</h3>
          <p class="text-sm text-gray-400">This may take a moment</p>
        </div>
      </div>
    `;

    try {
      const response = await this.apiCall('/collect', 'POST', {});

      if (response.ok) {
        this.showNotification('Collection started successfully', 'success');
        // Refresh data after a short delay
        setTimeout(() => this.loadDashboardData(), 3000);
      } else {
        throw new Error(`Collection failed: ${response.status}`);
      }
    } catch (error) {
      console.error('Collection failed:', error);
      this.showNotification('Collection failed', 'error');
    } finally {
      collectBtn.innerHTML = originalContent;
    }
  }

  private updateApiStatus(status: 'connecting' | 'connected' | 'error'): void {
    const statusElement = document.getElementById('api-status');
    if (!statusElement) return;

    const statusConfig = {
      connecting: { color: 'yellow', text: 'Connecting...' },
      connected: { color: 'green', text: 'API Online' },
      error: { color: 'red', text: 'API Error' }
    };

    const config = statusConfig[status];
    statusElement.innerHTML = `
      <div class="w-2 h-2 bg-${config.color}-400 rounded-full animate-pulse"></div>
      <span class="text-gray-300">${config.text}</span>
    `;
  }

  private getThreatColor(confidence: number): string {
    if (confidence >= 80) return 'red';
    if (confidence >= 60) return 'yellow';
    return 'gray';
  }

  private async apiCall(endpoint: string, method: string = 'GET', body?: any): Promise<Response> {
    const url = `${API_CONFIG.baseUrl}${endpoint}`;
    const options: RequestInit = {
      method,
      headers: {
        'X-Api-Key': API_CONFIG.apiKey,
        'Content-Type': 'application/json'
      }
    };

    if (body && method !== 'GET') {
      options.body = JSON.stringify(body);
    }

    return fetch(url, options);
  }

  private showNotification(message: string, type: 'success' | 'error' | 'warning'): void {
    const notification = document.createElement('div');
    const colors = {
      success: 'bg-green-500',
      error: 'bg-red-500',
      warning: 'bg-yellow-500'
    };

    notification.className = `fixed top-4 right-4 ${colors[type]} text-white px-4 py-2 rounded-lg shadow-lg z-50 transition-opacity`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
      notification.style.opacity = '0';
      setTimeout(() => notification.remove(), 300);
    }, 3000);
  }
}

// Declare lucide for TypeScript
declare global {
  interface Window {
    lucide: any;
  }
}

// Initialize dashboard when DOM is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new ThreatIntelligenceDashboard());
} else {
  new ThreatIntelligenceDashboard();
}

console.log('🛡️ Threat Intelligence Dashboard Module Loaded');