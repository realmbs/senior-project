/**
 * Confidence Distribution Widget
 * Visualizes confidence score distribution across ranges
 */

import { BaseChartWidget, type BaseChartState } from './base-chart-widget.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';

interface ConfidenceDistributionState extends BaseChartState {
  threats: ThreatIndicator[];
}

interface ConfidenceRangeData {
  label: string;
  min: number;
  max: number;
  count: number;
  percentage: number;
  color: string;
}

export class ConfidenceDistributionWidget extends BaseChartWidget<ConfidenceDistributionState> {
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
          this.initializeConfidenceChart();
        }, 0);
      }
    }

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('bar-chart-3', 'w-5 h-5 text-yellow-400');
    header.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Confidence Distribution'
    });
    header.appendChild(title);

    return header;
  }

  private createStatsSection(): HTMLElement {
    const { threats } = this.state;

    // Calculate statistics
    const avgConfidence = this.calculateAverageConfidence();
    const highRiskCount = threats.filter(t => t.confidence >= 80).length;
    const mediumRiskCount = threats.filter(t => t.confidence >= 60 && t.confidence < 80).length;
    const lowRiskCount = threats.filter(t => t.confidence < 60).length;

    const statsContainer = DOMBuilder.createElement('div', {
      className: 'mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3'
    });

    // Average confidence card
    const avgCard = this.createStatCard(
      'Average Confidence',
      `${avgConfidence}%`,
      'trending-up'
    );
    statsContainer.appendChild(avgCard);

    // High risk card
    const highRiskCard = this.createStatCard(
      'High Risk (≥80%)',
      highRiskCount.toString(),
      'alert-triangle'
    );
    statsContainer.appendChild(highRiskCard);

    // Risk distribution card
    const riskDistCard = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg p-4 border border-gray-600/30'
    });

    const riskDistTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-2 mb-3'
    });

    const riskIcon = DOMBuilder.createIcon('shield', 'w-4 h-4 text-blue-400');
    riskDistTitle.appendChild(riskIcon);

    const riskLabel = DOMBuilder.createElement('span', {
      className: 'text-sm font-semibold text-white',
      textContent: 'Risk Distribution'
    });
    riskDistTitle.appendChild(riskLabel);

    riskDistCard.appendChild(riskDistTitle);

    // Risk breakdown
    const riskBreakdown = DOMBuilder.createElement('div', {
      className: 'space-y-2 text-xs'
    });

    const highRow = this.createRiskRow('High', highRiskCount, '#ef4444');
    riskBreakdown.appendChild(highRow);

    const mediumRow = this.createRiskRow('Medium', mediumRiskCount, '#f97316');
    riskBreakdown.appendChild(mediumRow);

    const lowRow = this.createRiskRow('Low', lowRiskCount, '#3b82f6');
    riskBreakdown.appendChild(lowRow);

    riskDistCard.appendChild(riskBreakdown);
    statsContainer.appendChild(riskDistCard);

    // Data quality note for uniform data
    if (this.isConfidenceUniform()) {
      const noteContainer = DOMBuilder.createElement('div', {
        className: 'col-span-1 sm:col-span-3 mt-2'
      });

      const note = DOMBuilder.createElement('div', {
        className: 'bg-gray-700/30 rounded-lg p-3 border border-gray-600/30'
      });

      const noteText = DOMBuilder.createElement('p', {
        className: 'text-xs text-gray-400 italic'
      });
      noteText.textContent = 'OTX defaults to 75% confidence for automated pulses. Expect more variation as additional sources are integrated.';

      note.appendChild(noteText);
      noteContainer.appendChild(note);
      statsContainer.appendChild(noteContainer);
    }

    return statsContainer;
  }

  private createStatCard(label: string, value: string, iconName: string): HTMLElement {
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
      className: 'text-2xl font-bold text-white',
      textContent: value
    });
    card.appendChild(valueEl);

    return card;
  }

  private createRiskRow(label: string, count: number, color: string): HTMLElement {
    const row = DOMBuilder.createElement('div', {
      className: 'flex justify-between items-center'
    });

    const leftSection = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-2'
    });

    const colorDot = DOMBuilder.createElement('div', {
      className: 'w-2 h-2 rounded-full',
      style: { backgroundColor: color }
    });
    leftSection.appendChild(colorDot);

    const labelEl = DOMBuilder.createElement('span', {
      className: 'text-gray-400',
      textContent: label
    });
    leftSection.appendChild(labelEl);

    row.appendChild(leftSection);

    const valueEl = DOMBuilder.createElement('span', {
      className: 'font-semibold text-white',
      textContent: count.toString()
    });
    row.appendChild(valueEl);

    return row;
  }

  private calculateAverageConfidence(): number {
    const { threats } = this.state;
    if (threats.length === 0) return 0;

    const total = threats.reduce((sum, threat) => sum + (threat.confidence || 0), 0);
    return Math.round(total / threats.length);
  }

  private isConfidenceUniform(): boolean {
    const { threats } = this.state;
    if (threats.length === 0) return false;

    // Check if >90% of threats have the same confidence
    const confidenceMap = new Map<number, number>();
    threats.forEach(threat => {
      const conf = threat.confidence;
      confidenceMap.set(conf, (confidenceMap.get(conf) || 0) + 1);
    });

    const maxCount = Math.max(...Array.from(confidenceMap.values()));
    return (maxCount / threats.length) > 0.9;
  }

  private aggregateConfidenceRanges(): ConfidenceRangeData[] {
    const { threats } = this.state;

    const ranges = [
      { label: '0-49%', min: 0, max: 49, color: '#6b7280' },      // Gray-500
      { label: '50-59%', min: 50, max: 59, color: '#3b82f6' },    // Blue-500
      { label: '60-69%', min: 60, max: 69, color: '#eab308' },    // Yellow-500
      { label: '70-79%', min: 70, max: 79, color: '#f97316' },    // Orange-500
      { label: '80-89%', min: 80, max: 89, color: '#ef4444' },    // Red-500
      { label: '90-100%', min: 90, max: 100, color: '#dc2626' }   // Dark Red-600
    ];

    const total = threats.length;

    return ranges.map(range => {
      const count = threats.filter(
        t => t.confidence >= range.min && t.confidence <= range.max
      ).length;

      return {
        ...range,
        count,
        percentage: total > 0 ? (count / total) * 100 : 0
      };
    });
  }

  private initializeConfidenceChart(): void {
    const rangeData = this.aggregateConfidenceRanges();

    if (rangeData.length === 0) {
      console.warn('[ConfidenceDistributionWidget] No confidence data to display');
      return;
    }

    // Extract data for chart
    const labels = rangeData.map(d => d.label);
    const data = rangeData.map(d => d.count);
    const colors = rangeData.map(d => d.color);

    // Create chart configuration
    const config = {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Threat Count',
            data,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            callbacks: {
              label: (context: any) => {
                const value = context.parsed.y;
                const range = rangeData[context.dataIndex];
                const percentage = range.percentage.toFixed(1);
                return `${value} indicators (${percentage}% of total)`;
              },
              title: (tooltipItems: any[]) => {
                return `Confidence: ${tooltipItems[0].label}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              display: false
            },
            ticks: {
              font: {
                size: 11
              }
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
