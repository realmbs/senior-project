/**
 * ThreatCard Component
 * Displays individual threat intelligence indicators
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';

export interface ThreatIndicator {
  ioc_value: string;
  ioc_type: string;
  confidence: number;
  pulse_name: string;
  created_at: string;
  source: string;
  stix_data?: {
    pattern?: string;
    id?: string;
    labels?: string[];
    [key: string]: any;
  };
}

interface ThreatCardState {
  threat: ThreatIndicator;
  isLoading: boolean;
}

export class ThreatCard extends Component<ThreatCardState> {
  private onSearchClick?: (ioc: string) => void;

  constructor(threat: ThreatIndicator, onSearchClick?: (ioc: string) => void) {
    // Create container element
    const element = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg p-4 border border-gray-600/30 hover:border-gray-500/50 transition-colors'
    });

    super(element, { threat, isLoading: false });
    this.onSearchClick = onSearchClick;
    this.render();
    this.setupEventListeners();
  }

  render(): void {
    const { threat } = this.state;

    // Clear existing content
    DOMBuilder.clearChildren(this.element);

    // Create main container
    const container = DOMBuilder.createElement('div', {
      className: 'flex items-start justify-between'
    });

    // Create content section
    const content = DOMBuilder.createElement('div', {
      className: 'flex-1'
    });

    // Create badge container
    const badgeContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-2 mb-2'
    });

    // Create IOC type badge
    const iocBadge = DOMBuilder.createBadge(
      threat.ioc_type.toUpperCase(),
      this.getThreatColor(threat.confidence)
    );

    // Create confidence badge
    const confidenceBadge = DOMBuilder.createElement('span', {
      className: 'text-xs text-gray-400',
      textContent: `${threat.confidence}% confidence`
    });

    badgeContainer.appendChild(iocBadge);
    badgeContainer.appendChild(confidenceBadge);

    // Create IOC value display
    const iocValue = DOMBuilder.createElement('p', {
      className: 'text-white font-mono text-sm break-all',
      textContent: threat.ioc_value
    });

    // Create source display
    const sourceText = threat.pulse_name || threat.source || 'Unknown Source';
    const source = DOMBuilder.createElement('p', {
      className: 'text-gray-400 text-sm mt-1',
      textContent: sourceText
    });

    // Assemble content
    content.appendChild(badgeContainer);
    content.appendChild(iocValue);
    content.appendChild(source);

    // Create action button
    const actionButton = DOMBuilder.createElement('button', {
      className: 'search-threat-btn text-gray-400 hover:text-blue-400 transition-colors',
      dataset: { ioc: threat.ioc_value }
    });

    const actionIcon = DOMBuilder.createIcon('external-link', 'w-4 h-4');
    actionButton.appendChild(actionIcon);

    // Assemble main container
    container.appendChild(content);
    container.appendChild(actionButton);

    // Add to element
    this.element.appendChild(container);

    // Refresh icons
    this.refreshIcons();

    // Re-attach event listeners after render
    this.setupEventListeners();
  }

  update(newThreat: ThreatIndicator): void {
    this.setState({ threat: newThreat });
    this.render();
  }

  private setupEventListeners(): void {
    // Search button click handler
    const searchBtn = this.querySelector('.search-threat-btn');
    if (searchBtn && this.onSearchClick) {
      this.addEventListener(searchBtn, 'click', (e) => {
        e.preventDefault();
        const target = e.currentTarget as HTMLElement;
        const ioc = target.dataset.ioc;
        if (ioc && this.onSearchClick) {
          this.onSearchClick(ioc);
        }
      });
    }
  }

  private getThreatColor(confidence: number): 'red' | 'yellow' | 'gray' {
    if (confidence >= 80) return 'red';
    if (confidence >= 60) return 'yellow';
    return 'gray';
  }

  getIOCValue(): string {
    return this.state.threat.ioc_value;
  }

  getConfidence(): number {
    return this.state.threat.confidence;
  }

  getSource(): string {
    return this.state.threat.source;
  }
}