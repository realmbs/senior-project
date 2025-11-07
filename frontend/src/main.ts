import './style.css'
import { DOMBuilder } from './lib/dom-builder.js';
import { Component } from './lib/component.js';
import { MetricsWidget } from './components/metrics-widget.js';
import { ThreatList } from './components/threat-list.js';
import type { ThreatIndicator } from './components/threat-card.js';
import { enrichIndicator, detectIocType, collectThreats, type EnrichmentResponse } from './lib/api.js';
import { addCollectionMetric } from './lib/analytics-utils.js';
import { HeatmapWidget } from './components/heatmap-widget.js';
import { VisualAnalysisTriggerWidget } from './components/visual-analysis-trigger-widget.js';
import { VisualAnalysisModal } from './components/visual-analysis-modal.js';

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
  isLoadingFullDataset: boolean;
  apiStatus: 'connecting' | 'connected' | 'error';
  threatFilter: 'all' | 'high-risk' | 'recent';
  activeTab: 'ioc-lookup' | 'enrich';
}

class ThreatIntelligenceDashboard extends Component<DashboardState> {
  // Component instances
  private metricsWidgets: Map<string, MetricsWidget> = new Map();
  private threatList: ThreatList | null = null;
  private heatmapWidget: HeatmapWidget | null = null;
  private analyticsModal: VisualAnalysisModal | null = null;

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
      isLoadingFullDataset: false,
      apiStatus: 'connecting',
      threatFilter: 'all',
      activeTab: 'ioc-lookup'
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
      className: 'bg-gray-800/50 backdrop-blur-lg border-b border-gray-700/50 relative',
      style: { zIndex: '1000' }
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

    // Settings dropdown
    const settingsContainer = DOMBuilder.createElement('div', {
      className: 'relative'
    });

    const settingsBtn = DOMBuilder.createElement('button', {
      id: 'settings-btn',
      className: 'p-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors'
    });
    settingsBtn.appendChild(DOMBuilder.createIcon('settings', 'w-4 h-4'));

    const settingsDropdown = DOMBuilder.createElement('div', {
      id: 'settings-dropdown',
      className: 'hidden absolute right-0 mt-2 w-64 bg-gray-800 rounded-lg border border-gray-700 shadow-xl',
      style: { top: '100%', zIndex: '1100' }
    });

    // API Testing menu item
    const apiTestItem = DOMBuilder.createElement('a', {
      attributes: { href: '/api-test.html' },
      className: 'block px-4 py-3 hover:bg-gray-700/50 transition-colors'
    });

    const apiTestContent = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const apiTestIcon = DOMBuilder.createElement('div', {
      className: 'p-2 bg-green-500/20 rounded-lg'
    });
    apiTestIcon.appendChild(DOMBuilder.createIcon('settings', 'w-4 h-4 text-green-400'));

    const apiTestText = DOMBuilder.createElement('div');
    apiTestText.appendChild(DOMBuilder.createElement('div', {
      className: 'font-medium text-sm',
      textContent: 'API Testing'
    }));
    apiTestText.appendChild(DOMBuilder.createElement('div', {
      className: 'text-xs text-gray-400',
      textContent: 'Test API endpoints'
    }));

    apiTestContent.appendChild(apiTestIcon);
    apiTestContent.appendChild(apiTestText);
    apiTestItem.appendChild(apiTestContent);

    // Collection menu item
    const collectItem = DOMBuilder.createElement('button', {
      id: 'collect-btn',
      className: 'w-full block px-4 py-3 hover:bg-gray-700/50 transition-colors text-left'
    });

    const collectContent = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });

    const collectIcon = DOMBuilder.createElement('div', {
      className: 'p-2 bg-purple-500/20 rounded-lg'
    });
    collectIcon.appendChild(DOMBuilder.createIcon('download-cloud', 'w-4 h-4 text-purple-400'));

    const collectText = DOMBuilder.createElement('div');
    collectText.appendChild(DOMBuilder.createElement('div', {
      className: 'font-medium text-sm',
      textContent: 'Trigger Collection'
    }));
    collectText.appendChild(DOMBuilder.createElement('div', {
      className: 'text-xs text-gray-400',
      textContent: 'Collect new threat data'
    }));

    collectContent.appendChild(collectIcon);
    collectContent.appendChild(collectText);
    collectItem.appendChild(collectContent);

    settingsDropdown.appendChild(apiTestItem);
    settingsDropdown.appendChild(collectItem);
    settingsContainer.appendChild(settingsBtn);
    settingsContainer.appendChild(settingsDropdown);

    actions.appendChild(apiStatus);
    actions.appendChild(refreshBtn);
    actions.appendChild(settingsContainer);

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

  private createHeatmapSection(): HTMLElement {
    // Vertical stack container for heatmap and analytics trigger
    const container = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    // Heatmap widget container
    const heatmapSection = DOMBuilder.createElement('div', {
      id: 'heatmap-section'
    });
    container.appendChild(heatmapSection);

    // Analytics trigger widget container
    const analyticsSection = DOMBuilder.createElement('div', {
      id: 'analytics-trigger-section'
    });
    container.appendChild(analyticsSection);

    return container;
  }

  private createMetricsGrid(): HTMLElement {
    const grid = DOMBuilder.createElement('div', {
      id: 'metrics-grid',
      className: 'grid grid-cols-1 md:grid-cols-4 gap-6 mb-8'
    });

    // Create metric widget containers
    const metricConfigs = [
      { id: 'total-threats', label: 'All Threats', icon: 'alert-triangle', color: 'red' as const },
      { id: 'high-risk', label: 'High Risk', icon: 'shield-alert', color: 'red' as const },
      { id: 'recent-activity', label: 'Recent Activity', icon: 'activity', color: 'yellow' as const },
      { id: 'data-sources', label: 'Data Sources', icon: 'database', color: 'blue' as const }
    ];

    metricConfigs.forEach(config => {
      // Make data-sources clickable
      const isDataSources = config.id === 'data-sources';
      const container = DOMBuilder.createElement('div', {
        id: config.id + '-container',
        className: `bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6 ${isDataSources ? 'cursor-pointer hover:border-blue-500/50 transition-colors' : ''}`
      });

      grid.appendChild(container);
    });

    return grid;
  }

  private createContentGrid(): HTMLElement {
    const grid = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-1 lg:grid-cols-2 gap-8 items-start'
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

    // Title with filter button
    const titleContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2'
    });

    const filterButton = DOMBuilder.createElement('button', {
      id: 'threat-filter-btn',
      className: 'p-1 hover:bg-gray-700/50 rounded transition-colors relative'
    });
    filterButton.appendChild(DOMBuilder.createIcon('filter', 'w-5 h-5'));

    const title = DOMBuilder.createElement('h2', {
      className: 'text-lg font-semibold flex items-center'
    });
    title.appendChild(DOMBuilder.createElement('span', {
      id: 'threat-filter-label',
      textContent: 'All Threats'
    }));

    titleContainer.appendChild(filterButton);
    titleContainer.appendChild(title);

    // Filter dropdown (hidden by default)
    const filterDropdown = DOMBuilder.createElement('div', {
      id: 'threat-filter-dropdown',
      className: 'hidden absolute top-full left-0 mt-2 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-10 min-w-[180px]'
    });

    const filterOptions = [
      { value: 'all', label: 'All Threats', icon: 'list' },
      { value: 'high-risk', label: 'High Risk', icon: 'alert-triangle' },
      { value: 'recent', label: 'Recent Activity', icon: 'clock' }
    ];

    filterOptions.forEach(option => {
      const optionBtn = DOMBuilder.createElement('button', {
        className: 'threat-filter-option w-full px-4 py-2 text-left hover:bg-gray-700/50 transition-colors flex items-center space-x-2',
        dataset: { filter: option.value }
      });
      optionBtn.appendChild(DOMBuilder.createIcon(option.icon, 'w-4 h-4'));
      optionBtn.appendChild(DOMBuilder.createElement('span', { textContent: option.label }));
      filterDropdown.appendChild(optionBtn);
    });

    filterButton.appendChild(filterDropdown);

    const count = DOMBuilder.createElement('span', {
      id: 'threats-count',
      className: 'text-sm text-gray-400',
      textContent: '0 items'
    });

    headerContent.appendChild(titleContainer);
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

    // Heatmap and Analytics section
    const heatmapSection = this.createHeatmapSection();
    panel.appendChild(heatmapSection);

    // Quick actions moved to header settings dropdown

    return panel;
  }

  private createIOCLookupSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50'
    });

    // Tab Navigation Header
    const header = DOMBuilder.createElement('div', {
      className: 'p-6 border-b border-gray-700/50'
    });

    const tabNav = DOMBuilder.createElement('div', {
      className: 'flex space-x-1 bg-gray-700/30 rounded-lg p-1'
    });

    // IOC Lookup Tab
    const iocTab = DOMBuilder.createElement('button', {
      id: 'tab-ioc-lookup',
      className: 'flex-1 flex items-center justify-center space-x-2 px-4 py-2 rounded-md transition-colors bg-blue-600 text-white',
      dataset: { tab: 'ioc-lookup' }
    });
    iocTab.appendChild(DOMBuilder.createIcon('search', 'w-4 h-4'));
    iocTab.appendChild(DOMBuilder.createElement('span', { textContent: 'IOC Lookup' }));

    // Enrich Tab
    const enrichTab = DOMBuilder.createElement('button', {
      id: 'tab-enrich',
      className: 'flex-1 flex items-center justify-center space-x-2 px-4 py-2 rounded-md transition-colors text-gray-400 hover:text-white hover:bg-gray-700/50',
      dataset: { tab: 'enrich' }
    });
    enrichTab.appendChild(DOMBuilder.createIcon('globe', 'w-4 h-4'));
    enrichTab.appendChild(DOMBuilder.createElement('span', { textContent: 'Enrich IOC' }));

    tabNav.appendChild(iocTab);
    tabNav.appendChild(enrichTab);
    header.appendChild(tabNav);

    // Content Container
    const contentContainer = DOMBuilder.createElement('div', {
      id: 'tab-content-container',
      className: 'p-6'
    });

    // IOC Lookup Tab Content
    const iocLookupContent = this.createIOCLookupTabContent();
    contentContainer.appendChild(iocLookupContent);

    // Enrich Tab Content (hidden initially)
    const enrichContent = this.createEnrichTabContent();
    contentContainer.appendChild(enrichContent);

    section.appendChild(header);
    section.appendChild(contentContainer);

    return section;
  }

  private createIOCLookupTabContent(): HTMLElement {
    const content = DOMBuilder.createElement('div', {
      id: 'ioc-lookup-tab-content',
      className: 'space-y-4'
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
      className: 'mt-6 space-y-4 max-h-96 overflow-y-auto'
    });

    content.appendChild(form);
    content.appendChild(results);

    return content;
  }

  private createEnrichTabContent(): HTMLElement {
    const content = DOMBuilder.createElement('div', {
      id: 'enrich-tab-content',
      className: 'space-y-4 hidden'
    });

    const form = DOMBuilder.createElement('div', {
      className: 'space-y-4'
    });

    const inputContainer = DOMBuilder.createElement('div');
    const input = DOMBuilder.createElement('input', {
      id: 'enrich-input',
      attributes: {
        type: 'text',
        placeholder: 'Enter IP or domain to enrich...'
      },
      className: 'w-full px-3 py-2 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500'
    });
    inputContainer.appendChild(input);

    const button = DOMBuilder.createElement('button', {
      id: 'enrich-btn',
      className: 'w-full bg-purple-600 hover:bg-purple-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex items-center justify-center space-x-2'
    });
    button.appendChild(DOMBuilder.createIcon('globe', 'w-4 h-4'));
    button.appendChild(DOMBuilder.createElement('span', { textContent: 'Enrich IOC' }));

    form.appendChild(inputContainer);
    form.appendChild(button);

    const results = DOMBuilder.createElement('div', {
      id: 'enrich-results',
      className: 'mt-6 space-y-4'
    });

    content.appendChild(form);
    content.appendChild(results);

    return content;
  }

  // Deprecated: Quick actions moved to header settings dropdown
  // private createQuickActionsSection(): HTMLElement {
  //   const section = DOMBuilder.createElement('div', {
  //     className: 'grid grid-cols-1 gap-4'
  //   });
  //
  //   // API Testing link
  //   const apiTestLink = DOMBuilder.createElement('a', {
  //     attributes: { href: '/api-test.html' },
  //     className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-blue-500/50 transition-colors group block'
  //   });
  //
  //   const apiTestContent = DOMBuilder.createElement('div', {
  //     className: 'flex items-center space-x-3'
  //   });
  //
  //   const apiTestIcon = DOMBuilder.createElement('div', {
  //     className: 'p-2 bg-green-500/20 rounded-lg group-hover:bg-green-500/30 transition-colors'
  //   });
  //   apiTestIcon.appendChild(DOMBuilder.createIcon('settings', 'w-5 h-5 text-green-400'));
  //
  //   const apiTestText = DOMBuilder.createElement('div');
  //   apiTestText.appendChild(DOMBuilder.createElement('h3', {
  //     className: 'font-medium',
  //     textContent: 'API Testing'
  //   }));
  //   apiTestText.appendChild(DOMBuilder.createElement('p', {
  //     className: 'text-sm text-gray-400',
  //     textContent: 'Test API endpoints'
  //   }));
  //
  //   apiTestContent.appendChild(apiTestIcon);
  //   apiTestContent.appendChild(apiTestText);
  //   apiTestLink.appendChild(apiTestContent);
  //
  //   // Collection button
  //   const collectBtn = DOMBuilder.createElement('button', {
  //     id: 'collect-btn',
  //     className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-4 hover:border-purple-500/50 transition-colors group w-full text-left'
  //   });
  //
  //   const collectContent = DOMBuilder.createElement('div', {
  //     className: 'flex items-center space-x-3'
  //   });
  //
  //   const collectIcon = DOMBuilder.createElement('div', {
  //     className: 'p-2 bg-purple-500/20 rounded-lg group-hover:bg-purple-500/30 transition-colors'
  //   });
  //   collectIcon.appendChild(DOMBuilder.createIcon('download-cloud', 'w-5 h-5 text-purple-400'));
  //
  //   const collectText = DOMBuilder.createElement('div');
  //   collectText.appendChild(DOMBuilder.createElement('h3', {
  //     className: 'font-medium',
  //     textContent: 'Trigger Collection'
  //   }));
  //   collectText.appendChild(DOMBuilder.createElement('p', {
  //     className: 'text-sm text-gray-400',
  //     textContent: 'Collect new threat data'
  //   }));
  //
  //   collectContent.appendChild(collectIcon);
  //   collectContent.appendChild(collectText);
  //   collectBtn.appendChild(collectContent);
  //
  //   section.appendChild(apiTestLink);
  //   section.appendChild(collectBtn);
  //
  //   return section;
  // }

  private initializeComponents(): void {
    console.log('🔧 Initializing components...');

    // Initialize metrics widgets
    const metricConfigs = [
      { id: 'total-threats', label: 'All Threats', icon: 'alert-triangle', color: 'red' as const },
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

        // Add click handler for data-sources widget
        if (config.id === 'data-sources') {
          container.addEventListener('click', () => {
            this.showDataSourcesModal();
          });
          // Make sure container has pointer cursor
          container.style.cursor = 'pointer';
        }
      } else {
        console.error(`❌ Container not found: ${config.id}-container`);
      }
    });

    // Initialize heatmap widget
    const heatmapContainer = this.querySelector('#heatmap-section');
    if (heatmapContainer) {
      try {
        console.log('✅ Creating heatmap widget');
        this.heatmapWidget = new HeatmapWidget(heatmapContainer);
      } catch (error) {
        console.error('❌ Failed to create heatmap widget:', error);
        // Hide the heatmap section if it fails to load
        heatmapContainer.style.display = 'none';
      }
    } else {
      console.error('❌ Heatmap container not found: #heatmap-section');
    }

    // Initialize analytics modal (doesn't need a container, it creates its own overlay)
    try {
      console.log('✅ Creating analytics modal');
      const modalContainer = DOMBuilder.createElement('div');
      this.analyticsModal = new VisualAnalysisModal(modalContainer);
    } catch (error) {
      console.error('❌ Failed to create analytics modal:', error);
    }

    // Initialize analytics trigger widget
    const analyticsContainer = this.querySelector('#analytics-trigger-section');
    if (analyticsContainer) {
      try {
        console.log('✅ Creating analytics trigger widget');
        new VisualAnalysisTriggerWidget(
          analyticsContainer,
          () => this.openAnalyticsModal()
        );
      } catch (error) {
        console.error('❌ Failed to create analytics trigger widget:', error);
        analyticsContainer.style.display = 'none';
      }
    } else {
      console.error('❌ Analytics trigger container not found: #analytics-trigger-section');
    }

    // Initialize threat list
    const threatsContainer = this.querySelector('#threats-list');
    if (threatsContainer) {
      console.log('✅ Creating threat list component');
      this.threatList = new ThreatList(threatsContainer, (ioc) => this.handleThreatClick(ioc), 200);
    } else {
      console.error('❌ Threats container not found: #threats-list');
    }

    console.log(`✅ Components initialized: ${this.metricsWidgets.size} widgets, heatmap: ${this.heatmapWidget ? 'yes' : 'no'}, threat list: ${this.threatList ? 'yes' : 'no'}`);
  }

  private handleThreatClick(ioc: string): void {
    console.log('🔍 Threat clicked, IOC value:', ioc);
    const input = this.querySelector('#ioc-input') as HTMLInputElement;
    if (input) {
      input.value = ioc;
      console.log('✅ Input value set to:', input.value);
      // Small delay to ensure input is updated before search
      setTimeout(() => this.handleSearch(), 10);
    } else {
      console.error('❌ IOC input element not found');
    }
  }

  private openAnalyticsModal(): void {
    if (this.analyticsModal) {
      console.log('📊 Opening analytics modal with', this.state.recentThreats.length, 'threats');
      this.analyticsModal.openModal(this.state.recentThreats);
    } else {
      console.error('❌ Analytics modal not initialized');
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

    // Settings dropdown toggle
    const settingsBtn = this.querySelector('#settings-btn');
    const settingsDropdown = this.querySelector('#settings-dropdown');

    if (settingsBtn && settingsDropdown) {
      this.addEventListener(settingsBtn, 'click', (e) => {
        e.stopPropagation();
        settingsDropdown.classList.toggle('hidden');
        this.refreshIcons();
      });

      // Close dropdown when clicking outside
      document.addEventListener('click', () => {
        if (settingsDropdown && !settingsDropdown.classList.contains('hidden')) {
          settingsDropdown.classList.add('hidden');
        }
      });
    }

    // Filter button and dropdown
    const filterBtn = this.querySelector('#threat-filter-btn');
    const filterDropdown = this.querySelector('#threat-filter-dropdown');

    if (filterBtn && filterDropdown) {
      this.addEventListener(filterBtn, 'click', (e) => {
        e.stopPropagation();
        filterDropdown.classList.toggle('hidden');
        this.refreshIcons();
      });

      // Filter options
      const filterOptions = this.querySelectorAll('.threat-filter-option');
      filterOptions.forEach(option => {
        this.addEventListener(option, 'click', (e) => {
          e.stopPropagation();
          const filterValue = (e.currentTarget as HTMLElement).dataset.filter as 'all' | 'high-risk' | 'recent';
          this.setThreatFilter(filterValue);
          filterDropdown.classList.add('hidden');
        });
      });

      // Close dropdown when clicking outside
      this.addEventListener(document, 'click', () => {
        filterDropdown.classList.add('hidden');
      });
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
      this.addEventListener(collectBtn, 'click', () => {
        this.triggerCollection();
        // Close settings dropdown
        const settingsDropdown = this.querySelector('#settings-dropdown');
        if (settingsDropdown) {
          settingsDropdown.classList.add('hidden');
        }
      });
    }

    // Tab switching
    const iocTab = this.querySelector('#tab-ioc-lookup');
    const enrichTab = this.querySelector('#tab-enrich');

    if (iocTab) {
      this.addEventListener(iocTab, 'click', () => this.switchTab('ioc-lookup'));
    }

    if (enrichTab) {
      this.addEventListener(enrichTab, 'click', () => this.switchTab('enrich'));
    }

    // Enrich functionality
    const enrichBtn = this.querySelector('#enrich-btn');
    const enrichInput = this.querySelector('#enrich-input') as HTMLInputElement;

    if (enrichBtn) {
      this.addEventListener(enrichBtn, 'click', () => this.handleEnrich());
    }

    if (enrichInput) {
      this.addEventListener(enrichInput, 'keypress', (e) => {
        if (e.key === 'Enter') {
          this.handleEnrich();
        }
      });
    }
  }

  private async loadDashboardData(): Promise<void> {
    if (this.state.isLoading) return;

    console.log('📊 Loading initial dashboard data (Phase 1: Fast load)...');
    this.setState({ isLoading: true, apiStatus: 'connecting' });

    try {
      // Update API status
      this.updateApiStatus('connecting');

      // Phase 1: Load initial threats for fast render (150 items)
      console.log('📡 Phase 1: Making API call to /search?limit=150');
      const response = await this.apiCall('/search?limit=150');

      if (response.ok) {
        const data: SearchResponse = await response.json();
        const threats = data.results.results || [];
        console.log(`✅ Phase 1: Loaded ${threats.length} threats from API (initial display)`);

        // Calculate metrics from initial data
        const metricsData = this.calculateMetrics(threats);
        console.log('📈 Phase 1: Calculated initial metrics:', metricsData);

        // Update state
        this.setState({
          recentThreats: threats,
          metricsData,
          isLoading: false,
          apiStatus: 'connected'
        });

        // Update components
        console.log('🔄 Phase 1: Updating components...');
        this.updateMetricsDisplay();
        this.updateThreatsDisplay();
        this.updateApiStatus('connected');
        console.log('✅ Phase 1: Dashboard initial data loaded successfully');

        // Phase 2: Load full dataset in background (non-blocking)
        setTimeout(() => this.loadFullDataset(), 100);
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

  private async loadFullDataset(): Promise<void> {
    // Skip if already loading full dataset
    if (this.state.isLoadingFullDataset) return;

    console.log('📊 Phase 2: Loading full dataset in background...');
    this.setState({ isLoadingFullDataset: true });
    this.updateApiStatusFullDataset(true);

    try {
      console.log('📡 Phase 2: Making API call to /search?limit=10000');
      const response = await this.apiCall('/search?limit=10000');

      if (response.ok) {
        const data: SearchResponse = await response.json();
        const threats = data.results.results || [];
        console.log(`✅ Phase 2: Loaded ${threats.length} threats from API (full dataset)`);

        // Calculate metrics from full dataset
        const metricsData = this.calculateMetrics(threats);
        console.log('📈 Phase 2: Calculated full metrics:', metricsData);

        // Update state with full dataset
        this.setState({
          recentThreats: threats,
          metricsData,
          isLoadingFullDataset: false
        });

        // Update components with full data
        console.log('🔄 Phase 2: Updating components with full data...');
        this.updateMetricsDisplay();
        this.updateThreatsDisplay();
        this.updateApiStatusFullDataset(false);
        console.log('✅ Phase 2: Full dataset loaded successfully');
      } else {
        throw new Error(`API Error: ${response.status}`);
      }
    } catch (error) {
      console.error('❌ Phase 2: Failed to load full dataset:', error);
      this.setState({ isLoadingFullDataset: false });
      this.updateApiStatusFullDataset(false);
      // Don't show error notification - initial data is still displayed
      console.warn('⚠️ Continuing with initial dataset only');
    }
  }

  private calculateMetrics(threats: ThreatIndicator[]): DashboardMetrics {
    return {
      totalThreats: threats.length,
      highRiskThreats: threats.filter(t => t.confidence >= 80).length,
      recentActivity: threats.filter(t => {
        const created = new Date(t.created_at);
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        return created > sevenDaysAgo;
      }).length,
      topSources: [...new Set(threats.map(t => t.source).filter(s => s))].slice(0, 3)
    };
  }

  private updateMetricsDisplay(): void {
    const { metricsData, recentThreats } = this.state;

    // Update metrics widgets using component methods
    this.metricsWidgets.get('total-threats')?.updateValue(metricsData.totalThreats);
    this.metricsWidgets.get('high-risk')?.updateValue(metricsData.highRiskThreats);
    this.metricsWidgets.get('recent-activity')?.updateValue(metricsData.recentActivity);
    // Count active collection sources (otx, abuse_ch, etc.) - not enrichment services
    this.metricsWidgets.get('data-sources')?.updateValue(metricsData.topSources.length);

    // Update heatmap with latest threats (non-blocking - enrichment happens in background)
    if (this.heatmapWidget) {
      this.heatmapWidget.update(recentThreats).catch(error => {
        console.error('[Dashboard] Heatmap update failed:', error);
      });
    }

    // Update analytics modal if it's open
    if (this.analyticsModal) {
      this.analyticsModal.update(recentThreats);
    }
  }

  private updateThreatsDisplay(): void {
    const { recentThreats, threatFilter } = this.state;

    // Apply filter
    const filteredThreats = this.filterThreats(recentThreats, threatFilter);

    const countElement = this.querySelector('#threats-count');

    if (countElement) {
      countElement.textContent = `${filteredThreats.length} items`;
    }

    // Update threat list component
    if (this.threatList) {
      this.threatList.updateThreats(filteredThreats);
    }
  }

  private filterThreats(threats: ThreatIndicator[], filter: 'all' | 'high-risk' | 'recent'): ThreatIndicator[] {
    switch (filter) {
      case 'high-risk':
        return threats.filter(t => t.confidence >= 80);

      case 'recent':
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        return threats.filter(t => {
          const created = new Date(t.created_at);
          return created > sevenDaysAgo;
        });

      case 'all':
      default:
        return threats;
    }
  }

  private setThreatFilter(filter: 'all' | 'high-risk' | 'recent'): void {
    this.setState({ threatFilter: filter });

    // Update label
    const labelElement = this.querySelector('#threat-filter-label');
    const filterLabels = {
      'all': 'All Threats',
      'high-risk': 'High Risk',
      'recent': 'Recent Activity'
    };

    if (labelElement) {
      labelElement.textContent = filterLabels[filter];
    }

    // Re-render threats with new filter
    this.updateThreatsDisplay();
  }

  private switchTab(tabName: 'ioc-lookup' | 'enrich'): void {
    this.setState({ activeTab: tabName });

    // Update tab button styles
    const iocTab = this.querySelector('#tab-ioc-lookup');
    const enrichTab = this.querySelector('#tab-enrich');
    const iocContent = this.querySelector('#ioc-lookup-tab-content');
    const enrichContent = this.querySelector('#enrich-tab-content');

    if (tabName === 'ioc-lookup') {
      // Activate IOC Lookup tab (blue)
      iocTab?.classList.add('bg-blue-600', 'text-white');
      iocTab?.classList.remove('text-gray-400', 'hover:text-white', 'hover:bg-gray-700/50');

      enrichTab?.classList.remove('bg-purple-600', 'text-white');
      enrichTab?.classList.add('text-gray-400', 'hover:text-white', 'hover:bg-gray-700/50');

      iocContent?.classList.remove('hidden');
      enrichContent?.classList.add('hidden');
    } else {
      // Activate Enrich tab (purple)
      enrichTab?.classList.add('bg-purple-600', 'text-white');
      enrichTab?.classList.remove('text-gray-400', 'hover:text-white', 'hover:bg-gray-700/50');

      iocTab?.classList.remove('bg-blue-600', 'text-white');
      iocTab?.classList.add('text-gray-400', 'hover:text-white', 'hover:bg-gray-700/50');

      enrichContent?.classList.remove('hidden');
      iocContent?.classList.add('hidden');
    }

    this.refreshIcons();
  }

  private async handleEnrich(): Promise<void> {
    const input = this.querySelector('#enrich-input') as HTMLInputElement;
    const resultsContainer = this.querySelector('#enrich-results');
    const enrichBtn = this.querySelector('#enrich-btn');

    if (!input || !resultsContainer || !enrichBtn) return;

    const query = input.value.trim();
    if (!query) {
      this.showNotification('Please enter an IOC to enrich', 'warning');
      return;
    }

    // Show loading state
    this.setEnrichButtonLoading(enrichBtn, true);

    try {
      const iocType = detectIocType(query);
      console.log(`🔍 Enriching ${iocType}: ${query}`);

      const enrichmentData = await enrichIndicator(query, iocType);
      console.log('✅ Enrichment data received:', enrichmentData);

      this.displayEnrichResults(enrichmentData, resultsContainer);
    } catch (error) {
      console.error('❌ Enrichment failed:', error);
      this.showNotification('Enrichment failed', 'error');
      this.displayEnrichError(resultsContainer);
    } finally {
      this.setEnrichButtonLoading(enrichBtn, false);
    }
  }

  private setEnrichButtonLoading(button: HTMLElement, loading: boolean): void {
    DOMBuilder.clearChildren(button);

    if (loading) {
      button.appendChild(DOMBuilder.createElement('div', {
        className: 'animate-spin rounded-full h-4 w-4 border-b-2 border-white'
      }));
      button.appendChild(DOMBuilder.createElement('span', {
        textContent: 'Enriching...'
      }));
    } else {
      button.appendChild(DOMBuilder.createIcon('globe', 'w-4 h-4'));
      button.appendChild(DOMBuilder.createElement('span', {
        textContent: 'Enrich IOC'
      }));
      this.refreshIcons();
    }
  }

  private displayEnrichResults(data: EnrichmentResponse, container: HTMLElement): void {
    DOMBuilder.clearChildren(container);

    if (!data.enriched_indicators || data.enriched_indicators.length === 0) {
      container.appendChild(DOMBuilder.createElement('p', {
        className: 'text-gray-400',
        textContent: 'No enrichment data available for this IOC.'
      }));
      return;
    }

    const enriched = data.enriched_indicators[0];

    const resultsContainer = DOMBuilder.createElement('div', {
      className: 'space-y-4'
    });

    // Header with clear button
    const headerContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-between'
    });

    const header = DOMBuilder.createElement('h4', {
      className: 'text-sm font-medium text-gray-300',
      textContent: 'Enrichment Results'
    });

    const clearButton = DOMBuilder.createElement('button', {
      id: 'clear-enrich-btn',
      className: 'text-xs text-gray-400 hover:text-red-400 transition-colors flex items-center space-x-1'
    });
    clearButton.appendChild(DOMBuilder.createIcon('x', 'w-3 h-3'));
    clearButton.appendChild(DOMBuilder.createElement('span', { textContent: 'Clear' }));

    headerContainer.appendChild(header);
    headerContainer.appendChild(clearButton);
    resultsContainer.appendChild(headerContainer);

    // IOC Info Card
    const iocCard = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
    });

    const iocHeader = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-3'
    });
    iocHeader.appendChild(DOMBuilder.createIcon('info', 'w-4 h-4 text-blue-400'));
    iocHeader.appendChild(DOMBuilder.createElement('h5', {
      className: 'font-semibold text-white',
      textContent: 'IOC Information'
    }));
    iocCard.appendChild(iocHeader);

    const iocValue = DOMBuilder.createElement('p', {
      className: 'text-white font-mono text-sm break-all mb-2',
      textContent: enriched.ioc_value
    });
    iocCard.appendChild(iocValue);

    const iocTypeBadge = DOMBuilder.createBadge(enriched.ioc_type.toUpperCase(), 'blue');
    iocCard.appendChild(iocTypeBadge);

    resultsContainer.appendChild(iocCard);

    // Geolocation Data
    if (enriched.geolocation) {
      const geoCard = this.createEnrichResultCard('Geolocation', 'map-pin', [
        { label: 'Country', value: `${enriched.geolocation.country} (${enriched.geolocation.country_code})` },
        { label: 'City', value: `${enriched.geolocation.city}, ${enriched.geolocation.region}` },
        { label: 'Coordinates', value: `${enriched.geolocation.latitude}, ${enriched.geolocation.longitude}` },
        { label: 'ISP', value: enriched.geolocation.isp },
        { label: 'Organization', value: enriched.geolocation.org }
      ]);
      resultsContainer.appendChild(geoCard);
    }

    // Shodan Data
    if (enriched.shodan) {
      const shodanFields: Array<{ label: string, value: string }> = [
        { label: 'IP Address', value: enriched.shodan.ip },
        { label: 'Location', value: `${enriched.shodan.city}, ${enriched.shodan.country_name}` },
        { label: 'Organization', value: enriched.shodan.org }
      ];

      if (enriched.shodan.ports && enriched.shodan.ports.length > 0) {
        shodanFields.push({ label: 'Open Ports', value: enriched.shodan.ports.join(', ') });
      }

      if (enriched.shodan.vulns && enriched.shodan.vulns.length > 0) {
        shodanFields.push({ label: 'Vulnerabilities', value: enriched.shodan.vulns.join(', ') });
      }

      const shodanCard = this.createEnrichResultCard('Shodan Intelligence', 'server', shodanFields);
      resultsContainer.appendChild(shodanCard);
    }

    container.appendChild(resultsContainer);
    this.refreshIcons();

    // Setup clear button listener
    this.setupClearEnrichListener();
  }

  private createEnrichResultCard(title: string, icon: string, fields: Array<{ label: string, value: string }>): HTMLElement {
    const card = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
    });

    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-3'
    });
    header.appendChild(DOMBuilder.createIcon(icon, 'w-4 h-4 text-blue-400'));
    header.appendChild(DOMBuilder.createElement('h5', {
      className: 'font-semibold text-white',
      textContent: title
    }));

    const grid = DOMBuilder.createElement('div', {
      className: 'space-y-2 text-sm'
    });

    fields.forEach(field => {
      const row = DOMBuilder.createElement('div', {
        className: 'flex flex-col sm:flex-row'
      });

      const label = DOMBuilder.createElement('span', {
        className: 'text-gray-400 sm:w-1/3',
        textContent: field.label + ':'
      });

      const value = DOMBuilder.createElement('span', {
        className: 'text-white sm:w-2/3 break-all',
        textContent: field.value
      });

      row.appendChild(label);
      row.appendChild(value);
      grid.appendChild(row);
    });

    card.appendChild(header);
    card.appendChild(grid);

    return card;
  }

  private setupClearEnrichListener(): void {
    const clearBtn = this.querySelector('#clear-enrich-btn');
    if (clearBtn) {
      // Remove any existing listener first
      const newClearBtn = clearBtn.cloneNode(true) as HTMLElement;
      clearBtn.parentNode?.replaceChild(newClearBtn, clearBtn);

      this.addEventListener(newClearBtn, 'click', () => this.clearEnrichResults());
      this.refreshIcons();
    }
  }

  private clearEnrichResults(): void {
    const resultsContainer = this.querySelector('#enrich-results');
    const inputElement = this.querySelector('#enrich-input') as HTMLInputElement;

    if (resultsContainer) {
      DOMBuilder.clearChildren(resultsContainer);
    }

    if (inputElement) {
      inputElement.value = '';
      inputElement.focus();
    }
  }

  private displayEnrichError(container: HTMLElement): void {
    DOMBuilder.clearChildren(container);
    container.appendChild(DOMBuilder.createElement('p', {
      className: 'text-gray-400',
      textContent: 'Enrichment failed. Please try again.'
    }));
  }

  private async handleSearch(): Promise<void> {
    const input = this.querySelector('#ioc-input') as HTMLInputElement;
    const resultsContainer = this.querySelector('#search-results');
    const searchBtn = this.querySelector('#search-btn');

    if (!input || !resultsContainer || !searchBtn) {
      console.error('❌ Search elements not found:', { input: !!input, resultsContainer: !!resultsContainer, searchBtn: !!searchBtn });
      return;
    }

    const query = input.value.trim();
    console.log('🔍 Searching for IOC:', query);

    if (!query) {
      this.showNotification('Please enter an IOC to search', 'warning');
      return;
    }

    // Show loading state
    this.setSearchButtonLoading(searchBtn, true);

    try {
      const encodedQuery = encodeURIComponent(query);
      const searchUrl = `/search?q=${encodedQuery}&limit=50`;
      console.log('📡 Search API call:', searchUrl);

      const response = await this.apiCall(searchUrl);

      if (response.ok) {
        const data: SearchResponse = await response.json();
        console.log('✅ Search results:', data.results.results.length, 'threats found');
        console.log('📊 Results data:', data);
        this.displaySearchResults(data.results.results, resultsContainer);
      } else {
        const errorText = await response.text();
        console.error('❌ Search API error:', response.status, errorText);
        throw new Error(`Search failed: ${response.status}`);
      }
    } catch (error) {
      console.error('❌ Search failed with error:', error);
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

  private setupClearSearchListener(): void {
    const clearBtn = this.querySelector('#clear-search-btn');
    if (clearBtn) {
      // Remove any existing listener first
      const newClearBtn = clearBtn.cloneNode(true) as HTMLElement;
      clearBtn.parentNode?.replaceChild(newClearBtn, clearBtn);

      this.addEventListener(newClearBtn, 'click', () => this.clearSearchResults());
      this.refreshIcons();
    }
  }

  private clearSearchResults(): void {
    const resultsContainer = this.querySelector('#search-results');
    const inputElement = this.querySelector('#ioc-input') as HTMLInputElement;

    if (resultsContainer) {
      DOMBuilder.clearChildren(resultsContainer);
    }

    if (inputElement) {
      inputElement.value = '';
      inputElement.focus();
    }
  }

  private displaySearchResults(results: ThreatIndicator[], container: HTMLElement): void {
    DOMBuilder.clearChildren(container);

    if (results.length === 0) {
      // Empty state with clear button
      const emptyContainer = DOMBuilder.createElement('div', {
        className: 'space-y-3'
      });

      const headerContainer = DOMBuilder.createElement('div', {
        className: 'flex items-center justify-between'
      });

      const message = DOMBuilder.createElement('p', {
        className: 'text-gray-400',
        textContent: 'No threats found for this query.'
      });

      const clearButton = DOMBuilder.createElement('button', {
        id: 'clear-search-btn',
        className: 'text-xs text-gray-400 hover:text-red-400 transition-colors flex items-center space-x-1'
      });
      clearButton.appendChild(DOMBuilder.createIcon('x', 'w-3 h-3'));
      clearButton.appendChild(DOMBuilder.createElement('span', { textContent: 'Clear' }));

      headerContainer.appendChild(message);
      headerContainer.appendChild(clearButton);
      emptyContainer.appendChild(headerContainer);
      container.appendChild(emptyContainer);

      // Refresh icons and attach clear button event listener
      this.refreshIcons();
      this.setupClearSearchListener();
      return;
    }

    const resultsContainer = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    // Add header with clear button
    const headerContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-between'
    });

    const header = DOMBuilder.createElement('h4', {
      className: 'text-sm font-medium text-gray-300',
      textContent: `Search Results (${results.length})`
    });

    const clearButton = DOMBuilder.createElement('button', {
      id: 'clear-search-btn',
      className: 'text-xs text-gray-400 hover:text-red-400 transition-colors flex items-center space-x-1'
    });
    clearButton.appendChild(DOMBuilder.createIcon('x', 'w-3 h-3'));
    clearButton.appendChild(DOMBuilder.createElement('span', { textContent: 'Clear' }));

    headerContainer.appendChild(header);
    headerContainer.appendChild(clearButton);
    resultsContainer.appendChild(headerContainer);

    // Add results using DocumentFragment for efficiency
    const fragment = document.createDocumentFragment();
    results.forEach(threat => {
      const resultItem = this.createSearchResultItem(threat);
      fragment.appendChild(resultItem);
    });

    resultsContainer.appendChild(fragment);
    container.appendChild(resultsContainer);

    // Refresh icons and attach clear button event listener
    this.refreshIcons();
    this.setupClearSearchListener();
  }

  private createSearchResultItem(threat: ThreatIndicator): HTMLElement {
    const item = DOMBuilder.createElement('button', {
      className: 'bg-gray-700/20 rounded-lg p-3 border border-gray-600/20 hover:bg-gray-700/40 hover:border-blue-500/50 transition-all cursor-pointer w-full text-left',
      dataset: { threatData: JSON.stringify(threat) }
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

    // Add click handler to show modal
    item.addEventListener('click', () => this.showThreatDetailsModal(threat));

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
      // Use the proper API client with correct parameters
      const response = await collectThreats(['otx', 'abuse_ch'], 20, 'manual');

      // Collection started successfully (may still be processing in background)
      this.showNotification('Collection started - processing in background', 'success');

      // Log collection metrics for analytics
      addCollectionMetric({
        timestamp: new Date().toISOString(),
        source: 'manual',
        count: response.indicators_stored || 0,
        status: 'success'
      });

      // Refresh data after delay to allow background processing
      setTimeout(() => this.loadDashboardData(), 5000);
    } catch (error: any) {
      console.error('Collection request failed:', error);

      // Check if it's a timeout error (expected behavior)
      if (error.message?.includes('timeout') || error.name === 'TimeoutError') {
        this.showNotification('Collection started - may take 30-60s to complete', 'warning');

        // Log as warning since collection is likely processing
        addCollectionMetric({
          timestamp: new Date().toISOString(),
          source: 'manual',
          count: 0,
          status: 'warning'
        });

        // Still refresh after delay in case it completed
        setTimeout(() => this.loadDashboardData(), 10000);
      } else {
        this.showNotification('Collection failed - please try again', 'error');

        addCollectionMetric({
          timestamp: new Date().toISOString(),
          source: 'manual',
          count: 0,
          status: 'error'
        });
      }
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

  private updateApiStatusFullDataset(isLoading: boolean): void {
    const statusElement = this.querySelector('#api-status');
    if (!statusElement) return;

    DOMBuilder.clearChildren(statusElement);

    if (isLoading) {
      // Show "Loading full dataset..." indicator
      const indicator = DOMBuilder.createElement('div', {
        className: 'w-2 h-2 bg-blue-400 rounded-full animate-pulse'
      });

      const text = DOMBuilder.createElement('span', {
        className: 'text-gray-300',
        textContent: 'Loading full dataset...'
      });

      statusElement.appendChild(indicator);
      statusElement.appendChild(text);
    } else {
      // Show "All data loaded" indicator
      const indicator = DOMBuilder.createElement('div', {
        className: 'w-2 h-2 bg-green-400 rounded-full'
      });

      const text = DOMBuilder.createElement('span', {
        className: 'text-gray-300',
        textContent: 'All data loaded'
      });

      statusElement.appendChild(indicator);
      statusElement.appendChild(text);
    }
  }

  private getThreatColor(confidence: number): 'red' | 'yellow' | 'gray' {
    if (confidence >= 80) return 'red';
    if (confidence >= 60) return 'yellow';
    return 'gray';
  }

  private showThreatDetailsModal(threat: ThreatIndicator): void {
    // Create modal overlay
    const overlay = DOMBuilder.createElement('div', {
      id: 'threat-details-modal',
      className: 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    });

    // Create modal container
    const modal = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 rounded-xl border border-gray-700 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl'
    });

    // Modal header
    const header = DOMBuilder.createElement('div', {
      className: 'sticky top-0 bg-gray-800 border-b border-gray-700 p-6 flex items-center justify-between z-10'
    });

    const headerTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });
    headerTitle.appendChild(DOMBuilder.createIcon('shield-alert', 'w-6 h-6 text-blue-400'));
    headerTitle.appendChild(DOMBuilder.createElement('h2', {
      className: 'text-xl font-bold text-white',
      textContent: 'Threat Details'
    }));

    const closeButton = DOMBuilder.createElement('button', {
      id: 'close-modal-btn',
      className: 'p-2 hover:bg-gray-700 rounded-lg transition-colors'
    });
    closeButton.appendChild(DOMBuilder.createIcon('x', 'w-5 h-5 text-gray-400'));

    header.appendChild(headerTitle);
    header.appendChild(closeButton);

    // Modal content
    const content = DOMBuilder.createElement('div', {
      className: 'p-6 space-y-6'
    });

    // IOC Information
    const iocSection = this.createModalSection('IOC Information', [
      { label: 'IOC Value', value: threat.ioc_value, mono: true },
      { label: 'IOC Type', value: threat.ioc_type.toUpperCase() },
      { label: 'Confidence', value: `${threat.confidence}%`, badge: this.getThreatColor(threat.confidence) }
    ]);
    content.appendChild(iocSection);

    // Source Information
    const sourceSection = this.createModalSection('Source Information', [
      { label: 'Source', value: threat.source || 'Unknown' },
      { label: 'Pulse Name', value: threat.pulse_name || 'N/A' },
      { label: 'Created', value: new Date(threat.created_at).toLocaleString() }
    ]);
    content.appendChild(sourceSection);

    // STIX Data (if available)
    if (threat.stix_data) {
      const stixDetails: Array<{ label: string, value: string, mono?: boolean }> = [];

      if (threat.stix_data.pattern) {
        stixDetails.push({ label: 'Pattern', value: threat.stix_data.pattern, mono: true });
      }
      if (threat.stix_data.id) {
        stixDetails.push({ label: 'STIX ID', value: threat.stix_data.id, mono: true });
      }
      if (threat.stix_data.labels && Array.isArray(threat.stix_data.labels)) {
        stixDetails.push({ label: 'Labels', value: threat.stix_data.labels.join(', ') });
      }

      if (stixDetails.length > 0) {
        const stixSection = this.createModalSection('STIX 2.1 Data', stixDetails);
        content.appendChild(stixSection);
      }
    }

    // Enrichment section (Shodan data)
    const enrichmentSection = this.createEnrichmentSection();
    content.appendChild(enrichmentSection);

    // Raw JSON (expandable)
    const rawSection = this.createRawDataSection(threat);
    content.appendChild(rawSection);

    // Assemble modal
    modal.appendChild(header);
    modal.appendChild(content);
    overlay.appendChild(modal);

    // Add to body
    document.body.appendChild(overlay);

    // Refresh icons and setup close handlers
    this.refreshIcons();

    // Fetch enrichment data asynchronously
    this.fetchEnrichmentData(threat);

    // Close on button click
    closeButton.addEventListener('click', () => this.closeThreatDetailsModal());

    // Close on overlay click (not modal content)
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        this.closeThreatDetailsModal();
      }
    });

    // Close on Escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        this.closeThreatDetailsModal();
        document.removeEventListener('keydown', handleEscape);
      }
    };
    document.addEventListener('keydown', handleEscape);
  }

  private createModalSection(title: string, fields: Array<{ label: string, value: string, mono?: boolean, badge?: 'red' | 'yellow' | 'gray' }>): HTMLElement {
    const section = DOMBuilder.createElement('div');

    const sectionTitle = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-3 flex items-center space-x-2'
    });
    sectionTitle.appendChild(DOMBuilder.createIcon('info', 'w-4 h-4'));
    sectionTitle.appendChild(DOMBuilder.createElement('span', { textContent: title }));

    section.appendChild(sectionTitle);

    const grid = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    fields.forEach(field => {
      const row = DOMBuilder.createElement('div', {
        className: 'flex flex-col sm:flex-row sm:items-center'
      });

      const label = DOMBuilder.createElement('div', {
        className: 'text-sm text-gray-400 sm:w-1/3',
        textContent: field.label + ':'
      });

      const valueContainer = DOMBuilder.createElement('div', {
        className: 'sm:w-2/3'
      });

      if (field.badge) {
        valueContainer.appendChild(DOMBuilder.createBadge(field.value, field.badge));
      } else {
        const value = DOMBuilder.createElement('div', {
          className: `text-white ${field.mono ? 'font-mono text-sm' : ''} break-all`,
          textContent: field.value
        });
        valueContainer.appendChild(value);
      }

      row.appendChild(label);
      row.appendChild(valueContainer);
      grid.appendChild(row);
    });

    section.appendChild(grid);
    return section;
  }

  private createRawDataSection(threat: ThreatIndicator): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'border-t border-gray-700 pt-6'
    });

    const header = DOMBuilder.createElement('button', {
      id: 'toggle-raw-data',
      className: 'w-full flex items-center justify-between text-left hover:bg-gray-700/30 p-3 rounded-lg transition-colors'
    });

    const headerTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2'
    });
    headerTitle.appendChild(DOMBuilder.createIcon('code', 'w-4 h-4'));
    headerTitle.appendChild(DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Raw JSON Data'
    }));

    const chevron = DOMBuilder.createIcon('chevron-down', 'w-5 h-5 text-gray-400 transition-transform');

    header.appendChild(headerTitle);
    header.appendChild(chevron);

    const content = DOMBuilder.createElement('div', {
      id: 'raw-data-content',
      className: 'hidden mt-3'
    });

    const pre = DOMBuilder.createElement('pre', {
      className: 'bg-gray-900 rounded-lg p-4 overflow-x-auto text-xs text-green-400 font-mono'
    });
    pre.textContent = JSON.stringify(threat, null, 2);
    content.appendChild(pre);

    section.appendChild(header);
    section.appendChild(content);

    // Toggle functionality
    header.addEventListener('click', () => {
      content.classList.toggle('hidden');
      chevron.classList.toggle('rotate-180');
    });

    return section;
  }

  private createEnrichmentSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      id: 'enrichment-section',
      className: 'border-t border-gray-700 pt-6'
    });

    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-3'
    });
    header.appendChild(DOMBuilder.createIcon('globe', 'w-5 h-5 text-blue-400'));
    header.appendChild(DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Enrichment Data'
    }));

    const content = DOMBuilder.createElement('div', {
      id: 'enrichment-content',
      className: 'space-y-4'
    });

    // Loading state
    const loadingState = DOMBuilder.createElement('div', {
      id: 'enrichment-loading',
      className: 'flex items-center space-x-3 text-gray-400'
    });
    loadingState.appendChild(DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-5 w-5 border-b-2 border-blue-400'
    }));
    loadingState.appendChild(DOMBuilder.createElement('span', {
      textContent: 'Fetching enrichment data from Shodan...'
    }));

    content.appendChild(loadingState);

    section.appendChild(header);
    section.appendChild(content);

    return section;
  }

  private async fetchEnrichmentData(threat: ThreatIndicator): Promise<void> {
    try {
      // Detect IOC type and fetch enrichment data
      const iocType = detectIocType(threat.ioc_value);
      console.log(`🔍 Enriching ${iocType}: ${threat.ioc_value}`);

      const enrichmentData = await enrichIndicator(threat.ioc_value, iocType);
      console.log('✅ Enrichment data received:', enrichmentData);

      // Update the enrichment section with data
      this.displayEnrichmentData(enrichmentData);
    } catch (error) {
      console.error('❌ Failed to fetch enrichment data:', error);
      this.displayEnrichmentError();
    }
  }

  private displayEnrichmentData(data: EnrichmentResponse): void {
    const contentContainer = document.getElementById('enrichment-content');
    if (!contentContainer) return;

    DOMBuilder.clearChildren(contentContainer);

    if (!data.enriched_indicators || data.enriched_indicators.length === 0) {
      contentContainer.appendChild(DOMBuilder.createElement('p', {
        className: 'text-gray-400 text-sm',
        textContent: 'No enrichment data available for this indicator.'
      }));
      return;
    }

    const enriched = data.enriched_indicators[0];

    // Geolocation section
    if (enriched.geolocation) {
      const geoSection = this.createEnrichmentSubsection('Geolocation', 'map-pin', [
        { label: 'Country', value: `${enriched.geolocation.country} (${enriched.geolocation.country_code})` },
        { label: 'City', value: `${enriched.geolocation.city}, ${enriched.geolocation.region}` },
        { label: 'Coordinates', value: `${enriched.geolocation.latitude}, ${enriched.geolocation.longitude}` },
        { label: 'ISP', value: enriched.geolocation.isp },
        { label: 'Organization', value: enriched.geolocation.org },
        { label: 'Timezone', value: enriched.geolocation.timezone }
      ]);
      contentContainer.appendChild(geoSection);
    }

    // Shodan section
    if (enriched.shodan) {
      const shodanFields: Array<{ label: string, value: string }> = [
        { label: 'IP Address', value: enriched.shodan.ip },
        { label: 'Country', value: `${enriched.shodan.country_name} (${enriched.shodan.country_code})` },
        { label: 'City', value: enriched.shodan.city },
        { label: 'Organization', value: enriched.shodan.org },
        { label: 'ISP', value: enriched.shodan.isp }
      ];

      if (enriched.shodan.os) {
        shodanFields.push({ label: 'Operating System', value: enriched.shodan.os });
      }

      if (enriched.shodan.hostnames && enriched.shodan.hostnames.length > 0) {
        shodanFields.push({ label: 'Hostnames', value: enriched.shodan.hostnames.join(', ') });
      }

      if (enriched.shodan.ports && enriched.shodan.ports.length > 0) {
        shodanFields.push({ label: 'Open Ports', value: enriched.shodan.ports.join(', ') });
      }

      if (enriched.shodan.tags && enriched.shodan.tags.length > 0) {
        shodanFields.push({ label: 'Tags', value: enriched.shodan.tags.join(', ') });
      }

      if (enriched.shodan.vulns && enriched.shodan.vulns.length > 0) {
        shodanFields.push({ label: 'Vulnerabilities', value: enriched.shodan.vulns.join(', ') });
      }

      const shodanSection = this.createEnrichmentSubsection('Shodan Intelligence', 'server', shodanFields);
      contentContainer.appendChild(shodanSection);

      // Services section (if available)
      if (enriched.shodan.services && enriched.shodan.services.length > 0) {
        const servicesSection = this.createServicesSection(enriched.shodan.services);
        contentContainer.appendChild(servicesSection);
      }
    }

    this.refreshIcons();
  }

  private createEnrichmentSubsection(title: string, icon: string, fields: Array<{ label: string, value: string }>): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
    });

    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-3'
    });
    header.appendChild(DOMBuilder.createIcon(icon, 'w-4 h-4 text-blue-400'));
    header.appendChild(DOMBuilder.createElement('h4', {
      className: 'font-semibold text-white',
      textContent: title
    }));

    const grid = DOMBuilder.createElement('div', {
      className: 'space-y-2 text-sm'
    });

    fields.forEach(field => {
      const row = DOMBuilder.createElement('div', {
        className: 'flex flex-col sm:flex-row'
      });

      const label = DOMBuilder.createElement('span', {
        className: 'text-gray-400 sm:w-1/3',
        textContent: field.label + ':'
      });

      const value = DOMBuilder.createElement('span', {
        className: 'text-white sm:w-2/3 break-all',
        textContent: field.value
      });

      row.appendChild(label);
      row.appendChild(value);
      grid.appendChild(row);
    });

    section.appendChild(header);
    section.appendChild(grid);

    return section;
  }

  private createServicesSection(services: Array<{ port: number, protocol: string, product: string | null, version: string | null, banner: string }>): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
    });

    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-3'
    });
    header.appendChild(DOMBuilder.createIcon('terminal', 'w-4 h-4 text-blue-400'));
    header.appendChild(DOMBuilder.createElement('h4', {
      className: 'font-semibold text-white',
      textContent: `Detected Services (${services.length})`
    }));

    const servicesList = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    services.slice(0, 5).forEach(service => {
      const serviceCard = DOMBuilder.createElement('div', {
        className: 'bg-gray-800/50 rounded p-3 text-sm'
      });

      const portInfo = DOMBuilder.createElement('div', {
        className: 'flex items-center space-x-2 mb-2'
      });
      portInfo.appendChild(DOMBuilder.createBadge(`Port ${service.port}`, 'blue'));
      portInfo.appendChild(DOMBuilder.createElement('span', {
        className: 'text-gray-400',
        textContent: service.protocol.toUpperCase()
      }));

      serviceCard.appendChild(portInfo);

      if (service.product) {
        const productInfo = DOMBuilder.createElement('div', {
          className: 'text-white',
          textContent: `${service.product}${service.version ? ' ' + service.version : ''}`
        });
        serviceCard.appendChild(productInfo);
      }

      if (service.banner && service.banner.length > 0) {
        const banner = DOMBuilder.createElement('div', {
          className: 'mt-2 text-xs text-gray-400 font-mono bg-gray-900/50 p-2 rounded overflow-x-auto',
          textContent: service.banner.slice(0, 150) + (service.banner.length > 150 ? '...' : '')
        });
        serviceCard.appendChild(banner);
      }

      servicesList.appendChild(serviceCard);
    });

    if (services.length > 5) {
      const moreInfo = DOMBuilder.createElement('p', {
        className: 'text-xs text-gray-400 mt-2',
        textContent: `+ ${services.length - 5} more services`
      });
      servicesList.appendChild(moreInfo);
    }

    section.appendChild(header);
    section.appendChild(servicesList);

    return section;
  }

  private displayEnrichmentError(): void {
    const contentContainer = document.getElementById('enrichment-content');
    if (!contentContainer) return;

    DOMBuilder.clearChildren(contentContainer);

    const errorMessage = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 text-red-400 text-sm'
    });
    errorMessage.appendChild(DOMBuilder.createIcon('alert-circle', 'w-4 h-4'));
    errorMessage.appendChild(DOMBuilder.createElement('span', {
      textContent: 'Failed to fetch enrichment data. This IOC type may not support enrichment.'
    }));

    contentContainer.appendChild(errorMessage);
    this.refreshIcons();
  }

  private closeThreatDetailsModal(): void {
    const modal = document.getElementById('threat-details-modal');
    if (modal) {
      modal.remove();
    }
  }

  private showDataSourcesModal(): void {
    // Create modal overlay
    const overlay = DOMBuilder.createElement('div', {
      id: 'data-sources-modal',
      className: 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    });

    // Create modal container
    const modal = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 rounded-xl border border-gray-700 max-w-2xl w-full max-h-[90vh] overflow-y-auto shadow-2xl'
    });

    // Modal header
    const header = DOMBuilder.createElement('div', {
      className: 'sticky top-0 bg-gray-800 border-b border-gray-700 p-6 flex items-center justify-between z-10'
    });

    const headerTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });
    headerTitle.appendChild(DOMBuilder.createIcon('database', 'w-6 h-6 text-blue-400'));
    headerTitle.appendChild(DOMBuilder.createElement('h2', {
      className: 'text-xl font-bold text-white',
      textContent: 'Threat Intelligence Data Sources'
    }));

    const closeButton = DOMBuilder.createElement('button', {
      id: 'close-sources-modal-btn',
      className: 'p-2 hover:bg-gray-700 rounded-lg transition-colors'
    });
    closeButton.appendChild(DOMBuilder.createIcon('x', 'w-5 h-5 text-gray-400'));

    header.appendChild(headerTitle);
    header.appendChild(closeButton);

    // Modal content
    const content = DOMBuilder.createElement('div', {
      className: 'p-6 space-y-6'
    });

    // Get unique sources from threats (filter out undefined/null)
    const { recentThreats } = this.state;
    const sources = [...new Set(recentThreats.map(t => t.source).filter(s => s))];

    // Overview section
    const overviewSection = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
    });

    const overviewTitle = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-3 flex items-center space-x-2'
    });
    overviewTitle.appendChild(DOMBuilder.createIcon('info', 'w-4 h-4'));
    overviewTitle.appendChild(DOMBuilder.createElement('span', { textContent: 'Overview' }));

    const overviewStats = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-3 gap-4 text-sm'
    });

    const totalSources = DOMBuilder.createElement('div');
    totalSources.appendChild(DOMBuilder.createElement('div', {
      className: 'text-gray-400',
      textContent: 'Threat Feeds:'
    }));
    totalSources.appendChild(DOMBuilder.createElement('div', {
      className: 'text-white font-semibold text-lg',
      textContent: sources.length.toString()
    }));

    const totalEnrichment = DOMBuilder.createElement('div');
    totalEnrichment.appendChild(DOMBuilder.createElement('div', {
      className: 'text-gray-400',
      textContent: 'Enrichment:'
    }));
    totalEnrichment.appendChild(DOMBuilder.createElement('div', {
      className: 'text-white font-semibold text-lg',
      textContent: '2'
    }));

    const totalAllSources = DOMBuilder.createElement('div');
    totalAllSources.appendChild(DOMBuilder.createElement('div', {
      className: 'text-gray-400',
      textContent: 'Total Sources:'
    }));
    totalAllSources.appendChild(DOMBuilder.createElement('div', {
      className: 'text-white font-semibold text-lg',
      textContent: (sources.length + 2).toString()
    }));

    overviewStats.appendChild(totalSources);
    overviewStats.appendChild(totalEnrichment);
    overviewStats.appendChild(totalAllSources);
    overviewSection.appendChild(overviewTitle);
    overviewSection.appendChild(overviewStats);
    content.appendChild(overviewSection);

    // Data sources list
    const sourcesSection = DOMBuilder.createElement('div');

    const sourcesTitle = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-3 flex items-center space-x-2'
    });
    sourcesTitle.appendChild(DOMBuilder.createIcon('list', 'w-4 h-4'));
    sourcesTitle.appendChild(DOMBuilder.createElement('span', { textContent: 'Threat Intelligence Feeds' }));
    sourcesSection.appendChild(sourcesTitle);

    // Source details
    const sourcesList = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    const sourceInfo = {
      'otx': {
        name: 'AlienVault OTX',
        description: 'Open Threat Exchange - Community-driven threat intelligence',
        url: 'https://otx.alienvault.com',
        icon: 'shield'
      },
      'abuse.ch': {
        name: 'Abuse.ch',
        description: 'Feodo Tracker, URLhaus, and malware bazaar feeds',
        url: 'https://abuse.ch',
        icon: 'alert-octagon'
      }
    };

    sources.forEach(source => {
      const info = (sourceInfo as Record<string, typeof sourceInfo.otx>)[source] || {
        name: source.toUpperCase(),
        description: 'Threat intelligence feed',
        url: '#',
        icon: 'database'
      };

      const threatCount = recentThreats.filter(t => t.source === source).length;

      const sourceCard = DOMBuilder.createElement('div', {
        className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
      });

      const sourceHeader = DOMBuilder.createElement('div', {
        className: 'flex items-start justify-between mb-2'
      });

      const sourceLeft = DOMBuilder.createElement('div', {
        className: 'flex items-center space-x-3'
      });

      const sourceIconContainer = DOMBuilder.createElement('div', {
        className: 'p-2 bg-blue-500/20 rounded-lg'
      });
      sourceIconContainer.appendChild(DOMBuilder.createIcon(info.icon, 'w-5 h-5 text-blue-400'));

      const sourceNameContainer = DOMBuilder.createElement('div');
      sourceNameContainer.appendChild(DOMBuilder.createElement('h4', {
        className: 'font-semibold text-white',
        textContent: info.name
      }));
      sourceNameContainer.appendChild(DOMBuilder.createElement('p', {
        className: 'text-xs text-gray-400',
        textContent: info.description
      }));

      sourceLeft.appendChild(sourceIconContainer);
      sourceLeft.appendChild(sourceNameContainer);

      const sourceBadge = DOMBuilder.createBadge(`${threatCount} indicators`, 'blue');

      sourceHeader.appendChild(sourceLeft);
      sourceHeader.appendChild(sourceBadge);

      sourceCard.appendChild(sourceHeader);

      sourcesList.appendChild(sourceCard);
    });

    sourcesSection.appendChild(sourcesList);
    content.appendChild(sourcesSection);

    // Enrichment Sources section
    const enrichmentSection = DOMBuilder.createElement('div');

    const enrichmentTitle = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-3 flex items-center space-x-2'
    });
    enrichmentTitle.appendChild(DOMBuilder.createIcon('globe', 'w-4 h-4'));
    enrichmentTitle.appendChild(DOMBuilder.createElement('span', { textContent: 'Enrichment Sources' }));
    enrichmentSection.appendChild(enrichmentTitle);

    const enrichmentList = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    const enrichmentSources = [
      {
        name: 'Shodan',
        description: 'Internet-connected device intelligence, open ports, services, and vulnerabilities',
        icon: 'server',
        url: 'https://www.shodan.io',
        badge: 'Active'
      },
      {
        name: 'IP Geolocation',
        description: 'Geographic location, ISP, and organization data for IP addresses',
        icon: 'map-pin',
        url: 'https://ip-api.com',
        badge: 'Active'
      }
    ];

    enrichmentSources.forEach(enrichSource => {
      const enrichCard = DOMBuilder.createElement('div', {
        className: 'bg-gray-700/20 rounded-lg p-4 border border-gray-600/30'
      });

      const enrichHeader = DOMBuilder.createElement('div', {
        className: 'flex items-start justify-between mb-2'
      });

      const enrichLeft = DOMBuilder.createElement('div', {
        className: 'flex items-center space-x-3'
      });

      const enrichIconContainer = DOMBuilder.createElement('div', {
        className: 'p-2 bg-purple-500/20 rounded-lg'
      });
      enrichIconContainer.appendChild(DOMBuilder.createIcon(enrichSource.icon, 'w-5 h-5 text-purple-400'));

      const enrichNameContainer = DOMBuilder.createElement('div');
      enrichNameContainer.appendChild(DOMBuilder.createElement('h4', {
        className: 'font-semibold text-white',
        textContent: enrichSource.name
      }));
      enrichNameContainer.appendChild(DOMBuilder.createElement('p', {
        className: 'text-xs text-gray-400',
        textContent: enrichSource.description
      }));

      enrichLeft.appendChild(enrichIconContainer);
      enrichLeft.appendChild(enrichNameContainer);

      const enrichBadge = DOMBuilder.createBadge(enrichSource.badge, 'blue');

      enrichHeader.appendChild(enrichLeft);
      enrichHeader.appendChild(enrichBadge);

      enrichCard.appendChild(enrichHeader);

      enrichmentList.appendChild(enrichCard);
    });

    enrichmentSection.appendChild(enrichmentList);
    content.appendChild(enrichmentSection);

    // Assemble modal
    modal.appendChild(header);
    modal.appendChild(content);
    overlay.appendChild(modal);

    // Add to body
    document.body.appendChild(overlay);

    // Refresh icons and setup close handlers
    this.refreshIcons();

    // Close on button click
    closeButton.addEventListener('click', () => this.closeDataSourcesModal());

    // Close on overlay click
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        this.closeDataSourcesModal();
      }
    });

    // Close on Escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        this.closeDataSourcesModal();
        document.removeEventListener('keydown', handleEscape);
      }
    };
    document.addEventListener('keydown', handleEscape);
  }

  private closeDataSourcesModal(): void {
    const modal = document.getElementById('data-sources-modal');
    if (modal) {
      modal.remove();
    }
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