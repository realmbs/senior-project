/**
 * IOC Distribution Widget
 * Visualizes the breakdown of indicator types (domain, hostname, IPv4, URL, hash)
 */

import { BaseChartWidget, type BaseChartState } from './base-chart-widget.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';

interface IOCDistributionState extends BaseChartState {
  threats: ThreatIndicator[];
}

interface IOCTypeData {
  type: string;
  count: number;
  percentage: number;
  color: string;
}

export class IOCDistributionWidget extends BaseChartWidget<IOCDistributionState> {
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
          this.initializeDistributionChart();
        }, 0);
      }
    }

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('pie-chart', 'w-5 h-5 text-purple-400');
    header.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'IOC Type Distribution'
    });
    header.appendChild(title);

    return header;
  }

  private createStatsSection(): HTMLElement {
    const iocTypeData = this.aggregateIOCTypes();

    const statsContainer = DOMBuilder.createElement('div', {
      className: 'mt-4'
    });

    // Summary card
    const summaryCard = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg p-4 border border-gray-600/30'
    });

    // Title
    const summaryTitle = DOMBuilder.createElement('h4', {
      className: 'text-sm font-semibold text-white mb-3',
      textContent: 'Top IOC Types'
    });
    summaryCard.appendChild(summaryTitle);

    // Top 3 types
    const top3 = iocTypeData.slice(0, 3);
    const statsGrid = DOMBuilder.createElement('div', {
      className: 'space-y-2'
    });

    top3.forEach(item => {
      const row = DOMBuilder.createElement('div', {
        className: 'flex justify-between items-center'
      });

      const leftSection = DOMBuilder.createElement('div', {
        className: 'flex items-center gap-2'
      });

      // Color indicator
      const colorDot = DOMBuilder.createElement('div', {
        className: 'w-3 h-3 rounded-full flex-shrink-0',
        style: { backgroundColor: item.color }
      });
      leftSection.appendChild(colorDot);

      // Type name
      const typeLabel = DOMBuilder.createElement('span', {
        className: 'text-sm text-gray-300',
        textContent: item.type
      });
      leftSection.appendChild(typeLabel);

      row.appendChild(leftSection);

      // Count and percentage
      const rightSection = DOMBuilder.createElement('div', {
        className: 'flex items-center gap-2'
      });

      const count = DOMBuilder.createElement('span', {
        className: 'text-sm font-semibold text-white',
        textContent: item.count.toString()
      });
      rightSection.appendChild(count);

      const percentage = DOMBuilder.createElement('span', {
        className: 'text-xs text-gray-400',
        textContent: `(${item.percentage.toFixed(1)}%)`
      });
      rightSection.appendChild(percentage);

      row.appendChild(rightSection);
      statsGrid.appendChild(row);
    });

    summaryCard.appendChild(statsGrid);
    statsContainer.appendChild(summaryCard);

    return statsContainer;
  }

  private aggregateIOCTypes(): IOCTypeData[] {
    const { threats } = this.state;
    const typeMap = new Map<string, number>();

    // Count threats by IOC type
    threats.forEach(threat => {
      if (!threat.ioc_type) {
        console.warn('[IOCDistributionWidget] Threat missing ioc_type:', threat.ioc_value);
        return;
      }

      const type = threat.ioc_type.toUpperCase();
      typeMap.set(type, (typeMap.get(type) || 0) + 1);
    });

    const total = threats.length;

    // Convert to array and sort by count descending
    const typeData: IOCTypeData[] = Array.from(typeMap.entries())
      .map(([type, count]) => ({
        type,
        count,
        percentage: (count / total) * 100,
        color: this.getIOCTypeColor(type)
      }))
      .sort((a, b) => b.count - a.count);

    return typeData;
  }

  private getIOCTypeColor(iocType: string): string {
    const colors: Record<string, string> = {
      'DOMAIN': '#3b82f6',      // Blue-500
      'HOSTNAME': '#a855f7',    // Purple-500
      'IPV4': '#f97316',        // Orange-500
      'IPV6': '#f97316',        // Orange-500
      'URL': '#ef4444',         // Red-500
      'HASH': '#10b981',        // Green-500
      'MD5': '#10b981',         // Green-500
      'SHA1': '#10b981',        // Green-500
      'SHA256': '#10b981',      // Green-500
      'EMAIL': '#eab308',       // Yellow-500
      'FILEPATH': '#6366f1'     // Indigo-500
    };

    return colors[iocType] || '#6b7280'; // Default: Gray-500
  }

  private initializeDistributionChart(): void {
    const iocTypeData = this.aggregateIOCTypes();

    if (iocTypeData.length === 0) {
      console.warn('[IOCDistributionWidget] No IOC type data to display');
      return;
    }

    // Extract data for chart
    const labels = iocTypeData.map(d => d.type);
    const data = iocTypeData.map(d => d.count);
    const colors = iocTypeData.map(d => d.color);

    const totalCount = this.state.threats.length;

    // Create chart configuration
    const config = {
      type: 'doughnut',
      data: {
        labels,
        datasets: [
          {
            data,
            backgroundColor: colors,
            borderColor: '#1f2937', // Gray-800 to match background
            borderWidth: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '75%', // Large center hole for statistics
        plugins: {
          legend: {
            display: true,
            position: 'right' as const,
            labels: {
              boxWidth: 15,
              padding: 12,
              generateLabels: (chart: any) => {
                const data = chart.data;
                if (data.labels.length && data.datasets.length) {
                  return data.labels.map((label: string, i: number) => {
                    const value = data.datasets[0].data[i];
                    const percentage = ((value / totalCount) * 100).toFixed(1);
                    return {
                      text: `${label} (${percentage}%)`,
                      fillStyle: data.datasets[0].backgroundColor[i],
                      hidden: false,
                      index: i
                    };
                  });
                }
                return [];
              }
            }
          },
          tooltip: {
            callbacks: {
              label: (context: any) => {
                const label = context.label || '';
                const value = context.parsed;
                const percentage = ((value / totalCount) * 100).toFixed(1);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      },
      plugins: [
        {
          id: 'centerText',
          beforeDraw: (chart: any) => {
            const { ctx, chartArea } = chart;
            if (!chartArea) return;

            const centerX = (chartArea.left + chartArea.right) / 2;
            const centerY = (chartArea.top + chartArea.bottom) / 2;

            ctx.save();
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            // Total count
            ctx.font = 'bold 24px system-ui, -apple-system, sans-serif';
            ctx.fillStyle = '#ffffff'; // White
            ctx.fillText(totalCount.toString(), centerX, centerY - 10);

            // Label
            ctx.font = '12px system-ui, -apple-system, sans-serif';
            ctx.fillStyle = '#9ca3af'; // Gray-400
            ctx.fillText('Total IOCs', centerX, centerY + 15);

            ctx.restore();
          }
        }
      ]
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
