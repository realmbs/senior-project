/**
 * Visual Analysis Modal
 * Full-screen modal containing threat analytics charts
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';

// Import chart widgets (will be created next)
import type { TimelineChartWidget } from './timeline-chart-widget.js';
import type { SourceComparisonWidget } from './source-comparison-widget.js';
import type { CollectionActivityWidget } from './collection-activity-widget.js';

interface VisualAnalysisModalState {
  isOpen: boolean;
  threats: ThreatIndicator[];
}

export class VisualAnalysisModal extends Component<VisualAnalysisModalState> {
  private modalOverlay: HTMLElement | null = null;
  private timelineChart: any | null = null;
  private sourceComparisonChart: any | null = null;
  private collectionActivityWidget: any | null = null;

  constructor(element: HTMLElement) {
    super(element, {
      isOpen: false,
      threats: []
    });
  }

  render(): void {
    // Modal is rendered dynamically in openModal()
  }

  update(threats?: ThreatIndicator[]): void {
    if (threats) {
      this.setState({ threats });

      // Update charts if modal is open
      if (this.state.isOpen) {
        this.updateCharts(threats);
      }
    }
  }

  /**
   * Open the modal
   */
  openModal(threats: ThreatIndicator[]): void {
    if (this.state.isOpen) return;

    this.setState({ isOpen: true, threats });

    // Create modal overlay
    this.modalOverlay = DOMBuilder.createElement('div', {
      id: 'analytics-modal',
      className: 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    });

    // Create modal container
    const modal = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 rounded-xl border border-gray-700 w-full max-w-7xl max-h-[90vh] overflow-hidden shadow-2xl flex flex-col'
    });

    // Modal header
    const modalHeader = this.createModalHeader();
    modal.appendChild(modalHeader);

    // Modal content (scrollable)
    const modalContent = DOMBuilder.createElement('div', {
      className: 'flex-1 p-6 overflow-y-auto'
    });

    const chartsContainer = this.createChartsContainer();
    modalContent.appendChild(chartsContainer);

    modal.appendChild(modalContent);
    this.modalOverlay.appendChild(modal);

    // Add to body
    document.body.appendChild(this.modalOverlay);

    // Refresh icons after modal is added to DOM
    setTimeout(() => {
      if (window.lucide && window.lucide.createIcons) {
        window.lucide.createIcons();
      }
    }, 50);

    // Initialize charts after DOM is ready
    setTimeout(() => {
      this.initializeCharts(threats);
    }, 150);

    // Setup event listeners
    const closeButton = this.modalOverlay.querySelector('#close-analytics-modal-btn');
    if (closeButton) {
      closeButton.addEventListener('click', () => this.closeModal());
    }

    // Close on overlay click
    this.modalOverlay.addEventListener('click', (e) => {
      if (e.target === this.modalOverlay) {
        this.closeModal();
      }
    });

    // Close on Escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        this.closeModal();
        document.removeEventListener('keydown', handleEscape);
      }
    };
    document.addEventListener('keydown', handleEscape);
  }

  /**
   * Close the modal
   */
  closeModal(): void {
    if (!this.state.isOpen) return;

    this.setState({ isOpen: false });

    // Destroy charts
    if (this.timelineChart) {
      this.timelineChart.destroy();
      this.timelineChart = null;
    }
    if (this.sourceComparisonChart) {
      this.sourceComparisonChart.destroy();
      this.sourceComparisonChart = null;
    }
    if (this.collectionActivityWidget) {
      this.collectionActivityWidget.destroy();
      this.collectionActivityWidget = null;
    }

    // Remove modal from DOM
    if (this.modalOverlay && this.modalOverlay.parentNode) {
      this.modalOverlay.parentNode.removeChild(this.modalOverlay);
    }
    this.modalOverlay = null;
  }

  /**
   * Create modal header
   */
  private createModalHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 border-b border-gray-700 p-6 flex items-center justify-between'
    });

    // Title section
    const headerTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });
    headerTitle.appendChild(DOMBuilder.createIcon('bar-chart-2', 'w-6 h-6 text-purple-400'));

    const titleContainer = DOMBuilder.createElement('div');
    titleContainer.appendChild(DOMBuilder.createElement('h2', {
      className: 'text-xl font-bold text-white',
      textContent: 'Threat Analytics & Trends'
    }));
    titleContainer.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mt-1',
      textContent: 'Time-series analysis, source comparison, and collection insights'
    }));
    headerTitle.appendChild(titleContainer);

    // Close button
    const closeButton = DOMBuilder.createElement('button', {
      id: 'close-analytics-modal-btn',
      className: 'p-2 hover:bg-gray-700 rounded-lg transition-colors'
    });
    closeButton.appendChild(DOMBuilder.createIcon('x', 'w-5 h-5 text-gray-400'));

    header.appendChild(headerTitle);
    header.appendChild(closeButton);

    return header;
  }

  /**
   * Create charts container
   */
  private createChartsContainer(): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'space-y-6'
    });

    // Timeline chart (full width)
    const timelineSection = DOMBuilder.createElement('div', {
      id: 'timeline-chart-section',
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
    });
    container.appendChild(timelineSection);

    // Two-column grid for comparison and activity
    const gridSection = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-1 lg:grid-cols-2 gap-6'
    });

    // Source comparison (left)
    const sourceSection = DOMBuilder.createElement('div', {
      id: 'source-comparison-section',
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
    });
    gridSection.appendChild(sourceSection);

    // Collection activity (right)
    const activitySection = DOMBuilder.createElement('div', {
      id: 'collection-activity-section',
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
    });
    gridSection.appendChild(activitySection);

    container.appendChild(gridSection);

    return container;
  }

  /**
   * Initialize all charts
   */
  private async initializeCharts(threats: ThreatIndicator[]): Promise<void> {
    console.log('[VisualAnalysisModal] Starting chart initialization with', threats.length, 'threats');

    try {
      // Check if Chart.js is available
      if (typeof window.Chart === 'undefined') {
        console.error('[VisualAnalysisModal] Chart.js not loaded yet, retrying in 200ms...');
        setTimeout(() => this.initializeCharts(threats), 200);
        return;
      }

      console.log('[VisualAnalysisModal] Chart.js is available, importing widgets...');

      // Dynamically import chart widgets
      const { TimelineChartWidget } = await import('./timeline-chart-widget.js');
      const { SourceComparisonWidget } = await import('./source-comparison-widget.js');
      const { CollectionActivityWidget } = await import('./collection-activity-widget.js');

      console.log('[VisualAnalysisModal] Widgets imported successfully');

      // Get container elements
      const timelineContainer = document.getElementById('timeline-chart-section');
      const sourceContainer = document.getElementById('source-comparison-section');
      const activityContainer = document.getElementById('collection-activity-section');

      console.log('[VisualAnalysisModal] Containers found:', {
        timeline: !!timelineContainer,
        source: !!sourceContainer,
        activity: !!activityContainer
      });

      // Initialize timeline chart
      if (timelineContainer) {
        console.log('[VisualAnalysisModal] Creating TimelineChartWidget...');
        this.timelineChart = new TimelineChartWidget(timelineContainer);
        this.timelineChart.update(threats);
        console.log('[VisualAnalysisModal] TimelineChartWidget created and updated');
      }

      // Initialize source comparison chart
      if (sourceContainer) {
        console.log('[VisualAnalysisModal] Creating SourceComparisonWidget...');
        this.sourceComparisonChart = new SourceComparisonWidget(sourceContainer);
        this.sourceComparisonChart.update(threats);
        console.log('[VisualAnalysisModal] SourceComparisonWidget created and updated');
      }

      // Initialize collection activity widget
      if (activityContainer) {
        console.log('[VisualAnalysisModal] Creating CollectionActivityWidget...');
        this.collectionActivityWidget = new CollectionActivityWidget(activityContainer);
        this.collectionActivityWidget.update();
        console.log('[VisualAnalysisModal] CollectionActivityWidget created and updated');
      }

      console.log('[VisualAnalysisModal] All charts initialized successfully');
    } catch (error) {
      console.error('[VisualAnalysisModal] Failed to initialize charts:', error);
    }
  }

  /**
   * Update all charts with new data
   */
  private updateCharts(threats: ThreatIndicator[]): void {
    if (this.timelineChart) {
      this.timelineChart.update(threats);
    }
    if (this.sourceComparisonChart) {
      this.sourceComparisonChart.update(threats);
    }
    if (this.collectionActivityWidget) {
      this.collectionActivityWidget.update();
    }
  }
}
