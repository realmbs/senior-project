/**
 * Timeline Chart Widget
 * Displays threat detection trends over time with selectable periods
 */

import { BaseChartWidget, type BaseChartState } from './base-chart-widget.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';
import { aggregateByTime, type TimePeriod } from '../lib/analytics-utils.js';

interface TimelineChartState extends BaseChartState {
  threats: ThreatIndicator[];
  period: TimePeriod;
}

export class TimelineChartWidget extends BaseChartWidget<TimelineChartState> {
  constructor(element: HTMLElement) {
    const container = DOMBuilder.createElement('div', {
      className: 'w-full'
    });

    element.appendChild(container);

    super(container, {
      threats: [],
      period: 'daily',
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

    // Initialize chart if we have threats (wait for DOM to be ready)
    if (this.state.threats.length > 0 && !this.state.hasError && !this.state.isLoading) {
      setTimeout(() => {
        this.initializeTimelineChart();
      }, 0);
    }

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-between'
    });

    // Title section
    const titleSection = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('activity', 'w-5 h-5 text-blue-400');
    titleSection.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Threat Detection Timeline'
    });
    titleSection.appendChild(title);

    header.appendChild(titleSection);

    // Period selector tabs
    const periodTabs = this.createPeriodTabs();
    header.appendChild(periodTabs);

    return header;
  }

  private createPeriodTabs(): HTMLElement {
    const tabsContainer = DOMBuilder.createElement('div', {
      className: 'flex gap-2'
    });

    const periods: Array<{ value: TimePeriod; label: string }> = [
      { value: 'hourly', label: 'Hourly' },
      { value: 'daily', label: 'Daily' },
      { value: 'weekly', label: 'Weekly' }
    ];

    periods.forEach(({ value, label }) => {
      const isActive = this.state.period === value;

      const button = DOMBuilder.createElement('button', {
        className: isActive
          ? 'px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-medium transition-colors'
          : 'px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700/50 text-sm font-medium transition-colors',
        textContent: label
      });

      button.addEventListener('click', () => {
        this.setState({ period: value });
        this.render();
      });

      tabsContainer.appendChild(button);
    });

    return tabsContainer;
  }

  private initializeTimelineChart(): void {
    const { threats, period } = this.state;

    // Aggregate data by time period
    const { labels, values } = aggregateByTime(threats, period);

    // Create chart configuration
    const config = {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Threat Detections',
          data: values,
          borderColor: '#3b82f6', // Blue-500
          backgroundColor: 'rgba(59, 130, 246, 0.2)',
          tension: 0.4, // Smooth curves
          fill: true,
          pointRadius: 4,
          pointHoverRadius: 6,
          pointBackgroundColor: '#3b82f6',
          pointBorderColor: '#ffffff',
          pointBorderWidth: 2,
          pointHoverBackgroundColor: '#3b82f6',
          pointHoverBorderColor: '#ffffff',
          pointHoverBorderWidth: 3
        }]
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
              title: (context: any) => {
                return context[0].label;
              },
              label: (context: any) => {
                const count = context.parsed.y;
                return `${count} threat${count !== 1 ? 's' : ''} detected`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              display: true
            },
            ticks: {
              maxRotation: 45,
              minRotation: 0
            }
          },
          y: {
            beginAtZero: true,
            grid: {
              display: true
            },
            ticks: {
              stepSize: 1,
              callback: (value: any) => {
                if (Number.isInteger(value)) {
                  return value;
                }
                return null;
              }
            }
          }
        },
        interaction: {
          intersect: false,
          mode: 'index' as const
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
