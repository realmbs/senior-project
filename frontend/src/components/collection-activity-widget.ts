/**
 * Collection Activity Widget
 * Displays recent collection activity and performance metrics
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import {
  getCollectionMetrics,
  calculateCollectionStats,
  type CollectionMetric
} from '../lib/analytics-utils.js';

interface CollectionActivityState {
  metrics: CollectionMetric[];
  isLoading: boolean;
}

export class CollectionActivityWidget extends Component<CollectionActivityState> {
  constructor(element: HTMLElement) {
    const container = DOMBuilder.createElement('div', {
      className: 'w-full'
    });

    element.appendChild(container);

    super(container, {
      metrics: [],
      isLoading: false
    });

    this.render();
  }

  render(): void {
    DOMBuilder.clearChildren(this.element);

    // Header section
    const header = this.createHeader();
    this.element.appendChild(header);

    // Stats cards
    const statsCards = this.createStatsCards();
    this.element.appendChild(statsCards);

    // Recent collections table
    const recentTable = this.createRecentCollectionsTable();
    this.element.appendChild(recentTable);

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('clock', 'w-5 h-5 text-yellow-400');
    header.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Collection Activity'
    });
    header.appendChild(title);

    return header;
  }

  private createStatsCards(): HTMLElement {
    const { metrics } = this.state;
    const stats = calculateCollectionStats(metrics);

    const container = DOMBuilder.createElement('div', {
      className: 'mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3'
    });

    // Average duration card
    const durationCard = this.createStatCard(
      'Average Duration',
      stats.avgDuration > 0 ? `${(stats.avgDuration / 1000).toFixed(1)}s` : 'N/A',
      'text-blue-400',
      'clock'
    );
    container.appendChild(durationCard);

    // Success rate card
    const successCard = this.createStatCard(
      'Success Rate',
      metrics.length > 0 ? `${stats.successRate.toFixed(0)}%` : 'N/A',
      stats.successRate >= 90 ? 'text-green-400' : stats.successRate >= 70 ? 'text-yellow-400' : 'text-red-400',
      'check-circle'
    );
    container.appendChild(successCard);

    // Last collection card
    const lastCollectionText = stats.lastCollection
      ? this.formatRelativeTime(stats.lastCollection)
      : 'Never';

    const lastCard = this.createStatCard(
      'Last Collection',
      lastCollectionText,
      'text-gray-300',
      'database'
    );
    container.appendChild(lastCard);

    return container;
  }

  private createStatCard(label: string, value: string, valueClass: string, iconName: string): HTMLElement {
    const card = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg p-4 border border-gray-600/30'
    });

    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-2 mb-2'
    });

    const icon = DOMBuilder.createIcon(iconName, 'w-4 h-4 text-gray-400');
    header.appendChild(icon);

    const labelEl = DOMBuilder.createElement('span', {
      className: 'text-xs text-gray-400',
      textContent: label
    });
    header.appendChild(labelEl);

    card.appendChild(header);

    const valueEl = DOMBuilder.createElement('div', {
      className: `text-xl font-bold ${valueClass}`,
      textContent: value
    });
    card.appendChild(valueEl);

    return card;
  }

  private createRecentCollectionsTable(): HTMLElement {
    const { metrics } = this.state;

    const container = DOMBuilder.createElement('div', {
      className: 'mt-4'
    });

    const tableTitle = DOMBuilder.createElement('h4', {
      className: 'text-sm font-semibold text-gray-400 mb-3',
      textContent: 'Recent Collections'
    });
    container.appendChild(tableTitle);

    if (metrics.length === 0) {
      const emptyState = DOMBuilder.createElement('div', {
        className: 'bg-gray-700/30 rounded-lg p-6 text-center border border-gray-600/30'
      });

      const emptyIcon = DOMBuilder.createIcon('inbox', 'w-8 h-8 text-gray-500 mx-auto mb-2');
      emptyState.appendChild(emptyIcon);

      const emptyText = DOMBuilder.createElement('p', {
        className: 'text-sm text-gray-400',
        textContent: 'No collection data available yet'
      });
      emptyState.appendChild(emptyText);

      container.appendChild(emptyState);
      return container;
    }

    // Create table
    const table = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg border border-gray-600/30 overflow-hidden'
    });

    // Table header
    const tableHeader = DOMBuilder.createElement('div', {
      className: 'grid grid-cols-4 gap-4 px-4 py-3 bg-gray-700/50 border-b border-gray-600/30'
    });

    const headers = ['Timestamp', 'Source', 'Count', 'Status'];
    headers.forEach(headerText => {
      const th = DOMBuilder.createElement('div', {
        className: 'text-xs font-semibold text-gray-400 uppercase',
        textContent: headerText
      });
      tableHeader.appendChild(th);
    });

    table.appendChild(tableHeader);

    // Table body
    const tableBody = DOMBuilder.createElement('div', {
      className: 'divide-y divide-gray-600/30'
    });

    metrics.forEach(metric => {
      const row = DOMBuilder.createElement('div', {
        className: 'grid grid-cols-4 gap-4 px-4 py-3 hover:bg-gray-700/30 transition-colors'
      });

      // Timestamp
      const timestampCell = DOMBuilder.createElement('div', {
        className: 'text-sm text-gray-300',
        textContent: this.formatTimestamp(metric.timestamp)
      });
      row.appendChild(timestampCell);

      // Source
      const sourceCell = DOMBuilder.createElement('div', {
        className: 'text-sm text-gray-300 uppercase',
        textContent: metric.source
      });
      row.appendChild(sourceCell);

      // Count
      const countCell = DOMBuilder.createElement('div', {
        className: 'text-sm font-semibold text-blue-400',
        textContent: metric.count.toString()
      });
      row.appendChild(countCell);

      // Status
      const statusCell = DOMBuilder.createElement('div', {
        className: 'flex items-center gap-1'
      });

      const statusIcon = this.getStatusIcon(metric.status);
      statusCell.appendChild(statusIcon);

      const statusText = DOMBuilder.createElement('span', {
        className: this.getStatusTextClass(metric.status),
        textContent: this.getStatusLabel(metric.status)
      });
      statusCell.appendChild(statusText);

      row.appendChild(statusCell);

      tableBody.appendChild(row);
    });

    table.appendChild(tableBody);
    container.appendChild(table);

    return container;
  }

  private formatTimestamp(timestamp: string): string {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;

    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  private formatRelativeTime(timestamp: string): string {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;

    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  private getStatusIcon(status: string): HTMLElement {
    switch (status) {
      case 'success':
        return DOMBuilder.createIcon('check-circle', 'w-4 h-4 text-green-400');
      case 'warning':
        return DOMBuilder.createIcon('alert-circle', 'w-4 h-4 text-yellow-400');
      case 'error':
        return DOMBuilder.createIcon('x-circle', 'w-4 h-4 text-red-400');
      default:
        return DOMBuilder.createIcon('help-circle', 'w-4 h-4 text-gray-400');
    }
  }

  private getStatusTextClass(status: string): string {
    switch (status) {
      case 'success':
        return 'text-xs text-green-400';
      case 'warning':
        return 'text-xs text-yellow-400';
      case 'error':
        return 'text-xs text-red-400';
      default:
        return 'text-xs text-gray-400';
    }
  }

  private getStatusLabel(status: string): string {
    switch (status) {
      case 'success':
        return 'Success';
      case 'warning':
        return 'Warning';
      case 'error':
        return 'Error';
      default:
        return 'Unknown';
    }
  }

  update(): void {
    // Reload metrics from localStorage
    const metrics = getCollectionMetrics();
    this.setState({ metrics });
    this.render();
  }
}
