/**
 * Base Chart Widget
 * Provides Chart.js integration and lifecycle management for chart components
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';

// Declare Chart.js global from CDN
declare global {
  interface Window {
    Chart: any;
  }
}

export interface BaseChartState {
  isLoading: boolean;
  hasError: boolean;
  errorMessage?: string;
}

/**
 * Abstract base class for Chart.js widgets
 */
export abstract class BaseChartWidget<T extends BaseChartState = BaseChartState> extends Component<T> {
  protected chart: any = null;
  protected canvasElement: HTMLCanvasElement | null = null;

  constructor(element: HTMLElement, initialState: T) {
    super(element, initialState);

    // Initialize Chart.js defaults for glassmorphism theme
    this.initializeChartDefaults();
  }

  /**
   * Initialize Chart.js global defaults to match glassmorphism theme
   */
  private initializeChartDefaults(): void {
    if (typeof window.Chart !== 'undefined') {
      const Chart = window.Chart;

      // Set default colors
      Chart.defaults.color = '#9ca3af'; // Gray-400
      Chart.defaults.borderColor = '#374151'; // Gray-700
      Chart.defaults.backgroundColor = '#1f2937'; // Gray-800

      // Set default font
      Chart.defaults.font = {
        family: 'system-ui, -apple-system, sans-serif',
        size: 12,
        weight: 'normal'
      };

      // Configure responsive behavior
      Chart.defaults.responsive = true;
      Chart.defaults.maintainAspectRatio = false;

      // Configure interaction
      Chart.defaults.interaction = {
        intersect: false,
        mode: 'index'
      };
    }
  }

  /**
   * Create canvas element for chart
   */
  protected createCanvas(): HTMLCanvasElement {
    const canvas = DOMBuilder.createElement('canvas', {
      className: 'w-full h-full'
    }) as HTMLCanvasElement;

    this.canvasElement = canvas;
    return canvas;
  }

  /**
   * Initialize chart with configuration
   */
  protected initializeChart(config: any): void {
    if (!this.canvasElement) {
      console.error('[BaseChartWidget] Canvas element not found. Call createCanvas() first.');
      return;
    }

    if (typeof window.Chart === 'undefined') {
      console.error('[BaseChartWidget] Chart.js is not loaded. Make sure Chart.js CDN is included.');
      this.setState({ hasError: true, errorMessage: 'Chart.js not loaded' } as Partial<T>);
      return;
    }

    try {
      const ctx = this.canvasElement.getContext('2d');
      if (!ctx) {
        throw new Error('Could not get canvas context');
      }

      console.log('[BaseChartWidget] Initializing chart with config:', config.type);

      // Apply glassmorphic styling to config
      const styledConfig = this.applyGlassmorphicStyle(config);

      // Create chart
      this.chart = new window.Chart(ctx, styledConfig);

      console.log('[BaseChartWidget] Chart initialized successfully');
    } catch (error) {
      console.error('[BaseChartWidget] Failed to initialize chart:', error);
      this.setState({ hasError: true, errorMessage: 'Chart initialization failed' } as Partial<T>);
    }
  }

  /**
   * Apply glassmorphic styling to chart configuration
   */
  private applyGlassmorphicStyle(config: any): any {
    const styledConfig = { ...config };

    // Ensure plugins configuration exists
    if (!styledConfig.options) {
      styledConfig.options = {};
    }

    if (!styledConfig.options.plugins) {
      styledConfig.options.plugins = {};
    }

    // Style tooltip
    styledConfig.options.plugins.tooltip = {
      ...styledConfig.options.plugins.tooltip,
      backgroundColor: 'rgba(31, 41, 55, 0.9)', // Gray-800/90
      titleColor: '#f3f4f6', // Gray-100
      bodyColor: '#e5e7eb', // Gray-200
      borderColor: '#374151', // Gray-700
      borderWidth: 1,
      padding: 12,
      displayColors: true,
      boxPadding: 6
    };

    // Style legend
    if (!styledConfig.options.plugins.legend) {
      styledConfig.options.plugins.legend = {};
    }

    styledConfig.options.plugins.legend = {
      ...styledConfig.options.plugins.legend,
      labels: {
        color: '#9ca3af', // Gray-400
        padding: 16,
        font: {
          size: 12
        }
      }
    };

    // Style scales
    if (!styledConfig.options.scales) {
      styledConfig.options.scales = {};
    }

    // Style x-axis
    if (styledConfig.options.scales.x) {
      styledConfig.options.scales.x = {
        ...styledConfig.options.scales.x,
        grid: {
          color: '#374151', // Gray-700
          drawBorder: false
        },
        ticks: {
          color: '#9ca3af', // Gray-400
          font: {
            size: 11
          }
        }
      };
    }

    // Style y-axis
    if (styledConfig.options.scales.y) {
      styledConfig.options.scales.y = {
        ...styledConfig.options.scales.y,
        grid: {
          color: '#374151', // Gray-700
          drawBorder: false
        },
        ticks: {
          color: '#9ca3af', // Gray-400
          font: {
            size: 11
          }
        }
      };
    }

    return styledConfig;
  }

  /**
   * Update chart data
   */
  protected updateChartData(newData: any): void {
    if (!this.chart) {
      console.warn('Chart not initialized');
      return;
    }

    try {
      this.chart.data = newData;
      this.chart.update('none'); // Update without animation for performance
    } catch (error) {
      console.error('Failed to update chart:', error);
    }
  }

  /**
   * Update chart with animation
   */
  protected updateChartAnimated(newData: any): void {
    if (!this.chart) {
      console.warn('Chart not initialized');
      return;
    }

    try {
      this.chart.data = newData;
      this.chart.update(); // Update with animation
    } catch (error) {
      console.error('Failed to update chart:', error);
    }
  }

  /**
   * Resize chart
   */
  protected resizeChart(): void {
    if (this.chart) {
      this.chart.resize();
    }
  }

  /**
   * Render loading state
   */
  protected renderLoading(container: HTMLElement): void {
    DOMBuilder.clearChildren(container);

    const loadingDiv = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-center h-64'
    });

    const spinner = DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-8 w-8 border-2 border-blue-400 border-t-transparent'
    });

    loadingDiv.appendChild(spinner);
    container.appendChild(loadingDiv);
  }

  /**
   * Render error state
   */
  protected renderError(container: HTMLElement, message?: string): void {
    DOMBuilder.clearChildren(container);

    const errorDiv = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-center h-64 text-red-400'
    });

    const errorText = DOMBuilder.createElement('p', {
      className: 'text-sm'
    });
    errorText.textContent = message || 'Failed to load chart';

    errorDiv.appendChild(errorText);
    container.appendChild(errorDiv);
  }

  /**
   * Cleanup chart on destroy
   */
  destroy(): void {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }

    this.canvasElement = null;

    super.destroy();
  }
}
