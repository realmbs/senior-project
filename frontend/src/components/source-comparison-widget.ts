/**
 * Source Comparison Widget
 * Compares effectiveness of threat intelligence sources (OTX vs Abuse.ch)
 */

import { BaseChartWidget, type BaseChartState } from './base-chart-widget.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';
import { compareSourceEffectiveness } from '../lib/analytics-utils.js';

interface SourceComparisonState extends BaseChartState {
  threats: ThreatIndicator[];
}

export class SourceComparisonWidget extends BaseChartWidget<SourceComparisonState> {
  constructor(element: HTMLElement) {
    const container = DOMBuilder.createElement('div', {
      className: 'w-full'
    });

    element.appendChild(container);

    super(container, {
      threats: [],
      isLoading: false,
      hasError: false
    });

    this.render();
  }

  render(): void {
    DOMBuilder.clearChildren(this.element);

    // Header section
    const header = this.createHeader();
    this.element.appendChild(header);

    // Chart container
    const chartContainer = DOMBuilder.createElement('div', {
      className: 'mt-4',
      style: { height: '300px' }
    });

    if (this.state.hasError) {
      this.renderError(chartContainer, this.state.errorMessage);
    } else if (this.state.isLoading) {
      this.renderLoading(chartContainer);
    } else {
      const canvas = this.createCanvas();
      chartContainer.appendChild(canvas);
    }

    this.element.appendChild(chartContainer);

    // Stats section below chart
    if (this.state.threats.length > 0) {
      const stats = this.createStatsSection();
      this.element.appendChild(stats);

      // Initialize chart (wait for DOM to be ready)
      if (!this.state.hasError && !this.state.isLoading) {
        setTimeout(() => {
          this.initializeComparisonChart();
        }, 0);
      }
    }

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('shield-alert', 'w-5 h-5 text-green-400');
    header.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Source Effectiveness'
    });
    header.appendChild(title);

    return header;
  }

  private createStatsSection(): HTMLElement {
    const { threats } = this.state;
    const sourceStats = compareSourceEffectiveness(threats);

    const statsContainer = DOMBuilder.createElement('div', {
      className: 'mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3'
    });

    sourceStats.forEach(stat => {
      const statCard = DOMBuilder.createElement('div', {
        className: 'bg-gray-700/30 rounded-lg p-4 border border-gray-600/30'
      });

      // Source name
      const sourceName = DOMBuilder.createElement('div', {
        className: 'flex items-center justify-between mb-3'
      });

      const nameText = DOMBuilder.createElement('span', {
        className: 'text-sm font-semibold text-white uppercase',
        textContent: stat.source
      });
      sourceName.appendChild(nameText);

      // Confidence badge
      const confidenceBadge = DOMBuilder.createElement('span', {
        className: this.getConfidenceBadgeClass(stat.avgConfidence),
        textContent: `${stat.avgConfidence}% avg`
      });
      sourceName.appendChild(confidenceBadge);

      statCard.appendChild(sourceName);

      // Stats grid
      const statsGrid = DOMBuilder.createElement('div', {
        className: 'space-y-2 text-xs'
      });

      // Total indicators
      const totalRow = this.createStatRow('Total Indicators', stat.total.toString(), 'text-gray-300');
      statsGrid.appendChild(totalRow);

      // High confidence
      const highConfRow = this.createStatRow('High Confidence', stat.highConfidence.toString(), 'text-red-400');
      statsGrid.appendChild(highConfRow);

      // Recent activity
      const recentRow = this.createStatRow('Recent (7 days)', stat.recentActivity.toString(), 'text-green-400');
      statsGrid.appendChild(recentRow);

      // IOC types
      const typesRow = this.createStatRow('IOC Types', stat.iocTypes.length.toString(), 'text-blue-400');
      statsGrid.appendChild(typesRow);

      statCard.appendChild(statsGrid);

      statsContainer.appendChild(statCard);
    });

    return statsContainer;
  }

  private createStatRow(label: string, value: string, valueClass: string): HTMLElement {
    const row = DOMBuilder.createElement('div', {
      className: 'flex justify-between items-center'
    });

    const labelEl = DOMBuilder.createElement('span', {
      className: 'text-gray-400',
      textContent: label
    });
    row.appendChild(labelEl);

    const valueEl = DOMBuilder.createElement('span', {
      className: `font-semibold ${valueClass}`,
      textContent: value
    });
    row.appendChild(valueEl);

    return row;
  }

  private getConfidenceBadgeClass(confidence: number): string {
    if (confidence >= 80) {
      return 'px-2 py-1 rounded bg-red-500/20 text-red-400 text-xs font-medium';
    } else if (confidence >= 60) {
      return 'px-2 py-1 rounded bg-yellow-500/20 text-yellow-400 text-xs font-medium';
    } else {
      return 'px-2 py-1 rounded bg-blue-500/20 text-blue-400 text-xs font-medium';
    }
  }

  private initializeComparisonChart(): void {
    const { threats } = this.state;
    const sourceStats = compareSourceEffectiveness(threats);

    // Filter out any invalid entries and validate data
    const validStats = sourceStats.filter(s => s && s.source);

    if (validStats.length === 0) {
      console.warn('[SourceComparisonWidget] No valid source data to display');
      return;
    }

    // Extract data for chart
    const labels = validStats.map(s => s.source.toUpperCase());
    const totalData = validStats.map(s => s.total);
    const highConfidenceData = validStats.map(s => s.highConfidence);
    const recentActivityData = validStats.map(s => s.recentActivity);

    // Create chart configuration
    const config = {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Total Indicators',
            data: totalData,
            backgroundColor: 'rgba(59, 130, 246, 0.8)', // Blue-500
            borderColor: 'rgba(59, 130, 246, 1)',
            borderWidth: 1
          },
          {
            label: 'High Confidence (≥80%)',
            data: highConfidenceData,
            backgroundColor: 'rgba(239, 68, 68, 0.8)', // Red-500
            borderColor: 'rgba(239, 68, 68, 1)',
            borderWidth: 1
          },
          {
            label: 'Recent Activity (7d)',
            data: recentActivityData,
            backgroundColor: 'rgba(16, 185, 129, 0.8)', // Green-500
            borderColor: 'rgba(16, 185, 129, 1)',
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: 'top' as const,
            labels: {
              boxWidth: 12,
              padding: 10
            }
          },
          tooltip: {
            callbacks: {
              label: (context: any) => {
                const label = context.dataset.label || '';
                const value = context.parsed.y;
                return `${label}: ${value}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              display: false
            }
          },
          y: {
            beginAtZero: true,
            grid: {
              display: true
            },
            ticks: {
              stepSize: 10,
              callback: (value: any) => {
                if (Number.isInteger(value)) {
                  return value;
                }
                return null;
              }
            }
          }
        }
      }
    };

    this.initializeChart(config);
  }

  update(threats?: ThreatIndicator[]): void {
    if (threats) {
      this.setState({ threats });
      this.render();
    }
  }
}
