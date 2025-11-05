import './style.css'
import { DOMBuilder } from './lib/dom-builder.js';
import { Component } from './lib/component.js';
import { MetricsWidget } from './components/metrics-widget.js';
import { ThreatList } from './components/threat-list.js';
import type { ThreatIndicator } from './components/threat-card.js';

// API Configuration
const API_CONFIG = {
  baseUrl: 'https://u88kzux168.execute-api.us-east-1.amazonaws.com/dev',
  apiKey: 'mhxJBeDRDP515dkUrivFZ2B9IWY1Khx3cQkUh7jf'
};

// TypeScript interfaces for API responses
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

interface DashboardState {
  metricsData: DashboardMetrics;
  recentThreats: ThreatIndicator[];
  isLoading: boolean;
  apiStatus: 'connecting' | 'connected' | 'error';
}

class ThreatIntelligenceDashboard extends Component<DashboardState> {
  // Component instances
  private metricsWidgets: Map<string, MetricsWidget> = new Map();
  private threatList: ThreatList | null = null;

  // Auto-refresh interval
  private refreshInterval: number | null = null;

  constructor() {
    const app = document.querySelector('#app') as HTMLElement;
    if (!app) throw new Error('App container not found');

    super(app, {
      metricsData: {
        totalThreats: 0,
        highRiskThreats: 0,
        recentActivity: 0,
        topSources: []
      },
      recentThreats: [],
      isLoading: false,
      apiStatus: 'connecting'
    });

    this.init();
  }

  private async init(): Promise<void> {
    console.log('🛡️ Initializing Threat Intelligence Dashboard...');

    try {
      this.render();
      console.log('✅ Render completed');

      this.setupEventListeners();
      console.log('✅ Event listeners setup completed');

      // Load initial data
      await this.loadDashboardData();
      console.log('✅ Initial data load completed');

      // Set up auto-refresh every 5 minutes
      this.refreshInterval = window.setInterval(() => this.loadDashboardData(), 5 * 60 * 1000);

      console.log('✅ Dashboard initialized successfully');
    } catch (error) {
      console.error('❌ Dashboard initialization failed:', error);
    }
  }

  render(): void {
    // Clear existing content
    DOMBuilder.clearChildren(this.element);

    // Create main container
    const mainContainer = this.createMainContainer();
    this.element.appendChild(mainContainer);

    // Initialize components after DOM is ready
    setTimeout(() => {
      this.initializeComponents();
      this.refreshIcons();
    }, 0);
  }

  private createMainContainer(): HTMLElement {
    return DOMBuilder.createElement('div', {
      className: 'min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 text-white'
    }, [
      this.createHeader(),
      this.createMainContent()
    ]);
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('header', {
      className: 'bg-gray-800/50 backdrop-blur-lg border-b border-gray-700/50'
    });

    const container = DOMBuilder.createElement('div', {
      className: 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8'
    });

    const headerContent = DOMBuilder.createElement('div', {
      className: 'flex justify-between items-center h-16'
    });

    // Left side - branding
    const branding = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const logoContainer = DOMBuilder.createElement('div', {
      className: 'p-2 bg-blue-600 rounded-lg'
    });
    logoContainer.appendChild(DOMBuilder.createIcon('shield-check', 'w-6 h-6'));

    const textContainer = DOMBuilder.createElement('div');
    textContainer.appendChild(DOMBuilder.createElement('h1', {
      className: 'text-xl font-bold',
      textContent: 'Threat Intelligence v1.0'
    }));
    textContainer.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'Real-time Threat Intelligence Feed Analysis'
    }));

    branding.appendChild(logoContainer);
    branding.appendChild(textContainer);

    // Right side - status and actions
    const actions = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-4'
    });

    const apiStatus = DOMBuilder.createElement('div', {
      id: 'api-status',
      className: 'flex items-center space-x-2 text-sm'
    });
    apiStatus.appendChild(DOMBuilder.createElement('div', {
      className: 'w-2 h-2 bg-yellow-400 rounded-full animate-pulse'
    }));
    apiStatus.appendChild(DOMBuilder.createElement('span', {
      className: 'text-gray-300',
      textContent: 'Connecting...'
    }));

    const refreshBtn = DOMBuilder.createElement('button', {
      id: 'refresh-btn',
      className: 'p-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors'
    });
    refreshBtn.appendChild(DOMBuilder.createIcon('refresh-cw', 'w-4 h-4'));

    actions.appendChild(apiStatus);
    actions.appendChild(refreshBtn);

    headerContent.appendChild(branding);
    headerContent.appendChild(actions);
    container.appendChild(headerContent);
    header.appendChild(container);

    return header;
  }

  private createMainContent(): HTMLElement {
    const main = DOMBuilder.createElement('main', {
      className: 'max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8'
    });

    // Metrics grid
    const metricsGrid = this.createMetricsGrid();
    main.appendChild(metricsGrid);

    // Content grid
    const contentGrid = this.createContentGrid();
    main.appendChild(contentGrid);

    return main;
  }

  private createMetricsGrid(): HTMLElement {
    const grid = DOMBuilder.createElement('div', {
      id: 'metrics-grid',
      className: 'grid grid-cols-1 md:grid-cols-4 gap-6 mb-8'
    });

    // Create metric widget containers
    const metricConfigs = [
      { id: 'total-threats', label: 'Total Threats', icon: 'alert-triangle', color: 'red' as const },
      { id: 'high-risk', label: 'High Risk', icon: 'shield-alert', color: 'red' as const },
      { id: 'recent-activity', label: 'Recent Activity', icon: 'activity', color: 'yellow' as const },
      { id: 'data-sources', label: 'Data Sources', icon: 'database', color: 'blue' as const }
    ];

    metricConfigs.forEach(config => {
      const container = DOMBuilder.createElement('div', {
        id: config.id + '-container',
        className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
      });
      grid.appendChild(container);
    });

    return grid;
  }

  private createContentGrid(): HTMLElement {
    const grid = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-1 lg:grid-cols-2 gap-8'
    });

    // Threats panel
    const threatsPanel = this.createThreatsPanel();
    grid.appendChild(threatsPanel);

    // Actions panel
    const actionsPanel = this.createActionsPanel();
    grid.appendChild(actionsPanel);

    return grid;
  }

  private createThreatsPanel(): HTMLElement {
    const panel = DOMBuilder.createElement('div', {
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50'
    });

    // Header
    const header = DOMBuilder.createElement('div', {
      className: 'p-6 border-b border-gray-700/50'
    });

    const headerContent = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-between'
    });

    const title = DOMBuilder.createElement('h2', {
      className: 'text-lg font-semibold flex items-center space-x-2'
    });
    title.appendChild(DOMBuilder.createIcon('list', 'w-5 h-5'));
    title.appendChild(DOMBuilder.createElement('span', { textContent: 'Recent Threats' }));

    const count = DOMBuilder.createElement('span', {
      id: 'threats-count',
      className: 'text-sm text-gray-400',
      textContent: '0 items'
    });

    headerContent.appendChild(title);
    headerContent.appendChild(count);
    header.appendChild(headerContent);

    // Content container for ThreatList
    const content = DOMBuilder.createElement('div', {
      id: 'threats-list',
      className: 'p-6 space-y-4 max-h-96 overflow-y-auto'
    });

    panel.appendChild(header);
    panel.appendChild(content);

    return panel;
  }

  private createActionsPanel(): HTMLElement {
    const panel = DOMBuilder.createElement('div', {
      className: 'space-y-6'
    });

    // IOC Lookup section
    const lookupSection = this.createIOCLookupSection();
    panel.appendChild(lookupSection);

    // Quick actions
    const actionsSection = this.createQuickActionsSection();
    panel.appendChild(actionsSection);

    return panel;
  }

  private createIOCLookupSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50'
    });

    // Header
    const header = DOMBuilder.createElement('div', {
      className: 'p-6 border-b border-gray-700/50'
    });

    const title = DOMBuilder.createElement('h2', {
      className: 'text-lg font-semibold flex items-center space-x-2'
    });
    title.appendChild(DOMBuilder.createIcon('search', 'w-5 h-5'));
    title.appendChild(DOMBuilder.createElement('span', { textContent: 'IOC Lookup' }));

    header.appendChild(title);

    // Content
    const content = DOMBuilder.createElement('div', {
      className: 'p-6'
    });

    const form = DOMBuilder.createElement('div', {
      className: 'space-y-4'
    });

    const inputContainer = DOMBuilder.createElement('div');
    const input = DOMBuilder.createElement('input', {
      id: 'ioc-input',
      attributes: {
        type: 'text',
        placeholder: 'Enter IP, domain, or hash...'
      },
      className: 'w-full px-3 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500'
    });
    inputContainer.appendChild(input);

    const button = DOMBuilder.createElement('button', {
      id: 'search-btn',
      className: 'w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2'
    });
    button.appendChild(DOMBuilder.createIcon('search', 'w-4 h-4'));
    button.appendChild(DOMBuilder.createElement('span', { textContent: 'Search Threats' }));

    form.appendChild(inputContainer);
    form.appendChild(button);

    const results = DOMBuilder.createElement('div', {
      id: 'search-results',
      className: 'mt-6 space-y-4'
    });

    content.appendChild(form);
    content.appendChild(results);

    section.appendChild(header);
    section.appendChild(content);

    return section;
  }

  private createQuickActionsSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-1 gap-4'
    });

    // API Testing link
    const apiTestLink = DOMBuilder.createElement('a', {
      attributes: { href: '/api-test.html' },
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-blue-500/50 transition-colors group block'
    });

    const apiTestContent = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const apiTestIcon = DOMBuilder.createElement('div', {
      className: 'p-2 bg-green-500/20 rounded-lg group-hover:bg-green-500/30 transition-colors'
    });
    apiTestIcon.appendChild(DOMBuilder.createIcon('settings', 'w-5 h-5 text-green-400'));

    const apiTestText = DOMBuilder.createElement('div');
    apiTestText.appendChild(DOMBuilder.createElement('h3', {
      className: 'font-medium',
      textContent: 'API Testing'
    }));
    apiTestText.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'Test API endpoints'
    }));

    apiTestContent.appendChild(apiTestIcon);
    apiTestContent.appendChild(apiTestText);
    apiTestLink.appendChild(apiTestContent);

    // Collection button
    const collectBtn = DOMBuilder.createElement('button', {
      id: 'collect-btn',
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-purple-500/50 transition-colors group w-full text-left'
    });

    const collectContent = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const collectIcon = DOMBuilder.createElement('div', {
      className: 'p-2 bg-purple-500/20 rounded-lg group-hover:bg-purple-500/30 transition-colors'
    });
    collectIcon.appendChild(DOMBuilder.createIcon('download-cloud', 'w-5 h-5 text-purple-400'));

    const collectText = DOMBuilder.createElement('div');
    collectText.appendChild(DOMBuilder.createElement('h3', {
      className: 'font-medium',
      textContent: 'Trigger Collection'
    }));
    collectText.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'Collect new threat data'
    }));

    collectContent.appendChild(collectIcon);
    collectContent.appendChild(collectText);
    collectBtn.appendChild(collectContent);

    section.appendChild(apiTestLink);
    section.appendChild(collectBtn);

    return section;
  }

  private initializeComponents(): void {
    console.log('🔧 Initializing components...');

    // Initialize metrics widgets
    const metricConfigs = [
      { id: 'total-threats', label: 'Total Threats', icon: 'alert-triangle', color: 'red' as const },
      { id: 'high-risk', label: 'High Risk', icon: 'shield-alert', color: 'red' as const },
      { id: 'recent-activity', label: 'Recent Activity', icon: 'activity', color: 'yellow' as const },
      { id: 'data-sources', label: 'Data Sources', icon: 'database', color: 'blue' as const }
    ];

    metricConfigs.forEach(config => {
      const container = this.querySelector(`#${config.id}-container`);
      if (container) {
        console.log(`✅ Creating ${config.id} widget`);
        const widget = new MetricsWidget(container, config.label, config.icon, config.color);
        this.metricsWidgets.set(config.id, widget);
      } else {
        console.error(`❌ Container not found: ${config.id}-container`);
      }
    });

    // Initialize threat list
    const threatsContainer = this.querySelector('#threats-list');
    if (threatsContainer) {
      console.log('✅ Creating threat list component');
      this.threatList = new ThreatList(threatsContainer, (ioc) => this.handleThreatClick(ioc));
    } else {
      console.error('❌ Threats container not found: #threats-list');
    }

    console.log(`✅ Components initialized: ${this.metricsWidgets.size} widgets, threat list: ${this.threatList ? 'yes' : 'no'}`);
  }

  private handleThreatClick(ioc: string): void {
    const input = this.querySelector('#ioc-input') as HTMLInputElement;
    if (input) {
      input.value = ioc;
      this.handleSearch();
    }
  }

  update(): void {
    // Update is handled through state observers and component updates
  }

  private setupEventListeners(): void {
    // Refresh button
    const refreshBtn = this.querySelector('#refresh-btn');
    if (refreshBtn) {
      this.addEventListener(refreshBtn, 'click', () => this.loadDashboardData());
    }

    // Search functionality
    const searchBtn = this.querySelector('#search-btn');
    const iocInput = this.querySelector('#ioc-input') as HTMLInputElement;

    if (searchBtn) {
      this.addEventListener(searchBtn, 'click', () => this.handleSearch());
    }

    if (iocInput) {
      this.addEventListener(iocInput, 'keypress', (e) => {
        if (e.key === 'Enter') {
          this.handleSearch();
        }
      });
    }

    // Collection trigger
    const collectBtn = this.querySelector('#collect-btn');
    if (collectBtn) {
      this.addEventListener(collectBtn, 'click', () => this.triggerCollection());
    }
  }

  private async loadDashboardData(): Promise<void> {
    if (this.state.isLoading) return;

    console.log('📊 Loading dashboard data...');
    this.setState({ isLoading: true, apiStatus: 'connecting' });

    try {
      // Update API status
      this.updateApiStatus('connecting');

      // Load recent threats (last 50)
      console.log('📡 Making API call to /search?limit=50');
      const response = await this.apiCall('/search?limit=50');

      if (response.ok) {
        const data: SearchResponse = await response.json();
        const threats = data.results.results || [];
        console.log(`✅ Loaded ${threats.length} threats from API`);

        // Calculate metrics
        const metricsData = this.calculateMetrics(threats);
        console.log('📈 Calculated metrics:', metricsData);

        // Update state
        this.setState({
          recentThreats: threats,
          metricsData,
          isLoading: false,
          apiStatus: 'connected'
        });

        // Update components
        console.log('🔄 Updating components...');
        this.updateMetricsDisplay();
        this.updateThreatsDisplay();
        this.updateApiStatus('connected');
        console.log('✅ Dashboard data loaded successfully');
      } else {
        throw new Error(`API Error: ${response.status}`);
      }
    } catch (error) {
      console.error('❌ Failed to load dashboard data:', error);
      this.setState({ isLoading: false, apiStatus: 'error' });
      this.updateApiStatus('error');
      this.showNotification('Failed to load dashboard data', 'error');
    }
  }

  private calculateMetrics(threats: ThreatIndicator[]): DashboardMetrics {
    return {
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
    const { metricsData } = this.state;

    // Update metrics widgets using component methods
    this.metricsWidgets.get('total-threats')?.updateValue(metricsData.totalThreats);
    this.metricsWidgets.get('high-risk')?.updateValue(metricsData.highRiskThreats);
    this.metricsWidgets.get('recent-activity')?.updateValue(metricsData.recentActivity);
    this.metricsWidgets.get('data-sources')?.updateValue(metricsData.topSources.length);
  }

  private updateThreatsDisplay(): void {
    const { recentThreats } = this.state;
    const countElement = this.querySelector('#threats-count');

    if (countElement) {
      countElement.textContent = `${recentThreats.length} items`;
    }

    // Update threat list component
    if (this.threatList) {
      this.threatList.updateThreats(recentThreats);
    }
  }

  private async handleSearch(): Promise<void> {
    const input = this.querySelector('#ioc-input') as HTMLInputElement;
    const resultsContainer = this.querySelector('#search-results');
    const searchBtn = this.querySelector('#search-btn');

    if (!input || !resultsContainer || !searchBtn) return;

    const query = input.value.trim();
    if (!query) {
      this.showNotification('Please enter an IOC to search', 'warning');
      return;
    }

    // Show loading state
    this.setSearchButtonLoading(searchBtn, true);

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
      this.displaySearchError(resultsContainer);
    } finally {
      this.setSearchButtonLoading(searchBtn, false);
    }
  }

  private setSearchButtonLoading(button: HTMLElement, loading: boolean): void {
    DOMBuilder.clearChildren(button);

    if (loading) {
      button.appendChild(DOMBuilder.createElement('div', {
        className: 'animate-spin rounded-full h-4 w-4 border-b-2 border-white'
      }));
      button.appendChild(DOMBuilder.createElement('span', {
        textContent: 'Searching...'
      }));
    } else {
      button.appendChild(DOMBuilder.createIcon('search', 'w-4 h-4'));
      button.appendChild(DOMBuilder.createElement('span', {
        textContent: 'Search Threats'
      }));
      this.refreshIcons();
    }
  }

  private displaySearchError(container: HTMLElement): void {
    DOMBuilder.clearChildren(container);
    container.appendChild(DOMBuilder.createElement('p', {
      className: 'text-gray-400',
      textContent: 'Search failed. Please try again.'
    }));
  }

  private displaySearchResults(results: ThreatIndicator[], container: HTMLElement): void {
    DOMBuilder.clearChildren(container);

    if (results.length === 0) {
      container.appendChild(DOMBuilder.createElement('p', {
        className: 'text-gray-400',
        textContent: 'No threats found for this query.'
      }));
      return;
    }

    const resultsContainer = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    // Add header
    const header = DOMBuilder.createElement('h4', {
      className: 'text-sm font-medium text-gray-300',
      textContent: `Search Results (${results.length})`
    });
    resultsContainer.appendChild(header);

    // Add results using DocumentFragment for efficiency
    const fragment = document.createDocumentFragment();
    results.forEach(threat => {
      const resultItem = this.createSearchResultItem(threat);
      fragment.appendChild(resultItem);
    });

    resultsContainer.appendChild(fragment);
    container.appendChild(resultsContainer);
  }

  private createSearchResultItem(threat: ThreatIndicator): HTMLElement {
    const item = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-3 border border-gray-600/20'
    });

    // Badge container
    const badgeContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-1'
    });

    const iocBadge = DOMBuilder.createBadge(
      threat.ioc_type.toUpperCase(),
      this.getThreatColor(threat.confidence)
    );

    const confidenceBadge = DOMBuilder.createElement('span', {
      className: 'text-xs text-gray-400',
      textContent: `${threat.confidence}% confidence`
    });

    badgeContainer.appendChild(iocBadge);
    badgeContainer.appendChild(confidenceBadge);

    // IOC value
    const iocValue = DOMBuilder.createElement('p', {
      className: 'text-white font-mono text-sm break-all',
      textContent: threat.ioc_value
    });

    // Source
    const source = DOMBuilder.createElement('p', {
      className: 'text-gray-400 text-xs mt-1',
      textContent: threat.pulse_name || threat.source || 'Unknown Source'
    });

    item.appendChild(badgeContainer);
    item.appendChild(iocValue);
    item.appendChild(source);

    return item;
  }

  private async triggerCollection(): Promise<void> {
    const collectBtn = this.querySelector('#collect-btn');
    if (!collectBtn) return;

    // Store original content
    const originalContent = collectBtn.cloneNode(true) as HTMLElement;

    // Set loading state
    this.setCollectionButtonLoading(collectBtn, true);

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
      // Restore original content
      DOMBuilder.clearChildren(collectBtn);
      while (originalContent.firstChild) {
        collectBtn.appendChild(originalContent.firstChild);
      }
      this.refreshIcons();
    }
  }

  private setCollectionButtonLoading(button: HTMLElement, loading: boolean): void {
    if (!loading) return; // Restoration is handled in finally block

    DOMBuilder.clearChildren(button);

    const container = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const iconContainer = DOMBuilder.createElement('div', {
      className: 'p-2 bg-purple-500/20 rounded-lg'
    });

    const spinner = DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-5 w-5 border-b-2 border-purple-400'
    });

    iconContainer.appendChild(spinner);

    const textContainer = DOMBuilder.createElement('div');
    textContainer.appendChild(DOMBuilder.createElement('h3', {
      className: 'font-medium',
      textContent: 'Collecting...'
    }));
    textContainer.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'This may take a moment'
    }));

    container.appendChild(iconContainer);
    container.appendChild(textContainer);
    button.appendChild(container);
  }

  private updateApiStatus(status: 'connecting' | 'connected' | 'error'): void {
    const statusElement = this.querySelector('#api-status');
    if (!statusElement) return;

    const statusConfig = {
      connecting: { color: 'yellow', text: 'Connecting...' },
      connected: { color: 'green', text: 'API Online' },
      error: { color: 'red', text: 'API Error' }
    };

    const config = statusConfig[status];
    DOMBuilder.clearChildren(statusElement);

    const indicator = DOMBuilder.createElement('div', {
      className: `w-2 h-2 bg-${config.color}-400 rounded-full animate-pulse`
    });

    const text = DOMBuilder.createElement('span', {
      className: 'text-gray-300',
      textContent: config.text
    });

    statusElement.appendChild(indicator);
    statusElement.appendChild(text);
  }

  private getThreatColor(confidence: number): 'red' | 'yellow' | 'gray' {
    if (confidence >= 80) return 'red';
    if (confidence >= 60) return 'yellow';
    return 'gray';
  }

  // Enhanced cleanup with proper component lifecycle management
  destroy(): void {
    // Clear auto-refresh interval
    if (this.refreshInterval) {
      window.clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }

    // Destroy all metric widgets
    for (const widget of this.metricsWidgets.values()) {
      widget.destroy();
    }
    this.metricsWidgets.clear();

    // Destroy threat list
    if (this.threatList) {
      this.threatList.destroy();
      this.threatList = null;
    }

    // Call parent destroy
    super.destroy();

    console.log('🛡️ Dashboard destroyed and cleaned up');
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