/**
 * MetricsWidget Component
 * Displays dashboard metrics with reactive updates
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';

interface MetricsWidgetState {
  value: number | string;
  label: string;
  icon: string;
  color: 'red' | 'yellow' | 'blue' | 'green';
  isLoading: boolean;
}

export class MetricsWidget extends Component<MetricsWidgetState> {
  constructor(
    container: HTMLElement,
    label: string,
    icon: string,
    color: 'red' | 'yellow' | 'blue' | 'green' = 'blue',
    initialValue: number | string = 'Loading...'
  ) {
    super(container, {
      value: initialValue,
      label,
      icon,
      color,
      isLoading: typeof initialValue === 'string'
    });

    this.setupObservers();
    this.render();
  }

  render(): void {
    const { label, icon, color, value, isLoading } = this.state;

    // Clear existing content
    DOMBuilder.clearChildren(this.element);

    // Create main container
    const container = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-between'
    });

    // Create content section
    const content = DOMBuilder.createElement('div');

    // Create label
    const labelElement = DOMBuilder.createElement('p', {
      className: 'text-gray-400 text-sm',
      textContent: label
    });

    // Create value display
    const valueElement = DOMBuilder.createElement('p', {
      className: `text-2xl font-bold text-white value-display ${isLoading ? 'animate-pulse' : ''}`,
      textContent: value.toString()
    });

    content.appendChild(labelElement);
    content.appendChild(valueElement);

    // Create icon container
    const iconContainer = DOMBuilder.createElement('div', {
      className: `p-3 bg-${color}-500/20 rounded-lg`
    });

    const iconElement = DOMBuilder.createIcon(icon, `w-6 h-6 text-${color}-400`);
    iconContainer.appendChild(iconElement);

    // Assemble container
    container.appendChild(content);
    container.appendChild(iconContainer);

    // Add to element
    this.element.appendChild(container);

    // Refresh icons with error handling
    try {
      this.refreshIcons();
    } catch (error) {
      console.warn('Icon refresh failed for metrics widget:', error);
    }
  }

  private setupObservers(): void {
    // Observe value changes and update display
    this.observe('value', () => {
      const valueElement = this.querySelector('.value-display');
      if (valueElement) {
        valueElement.textContent = this.state.value.toString();
        valueElement.classList.remove('animate-pulse');
      }
    });

    this.observe('isLoading', () => {
      const valueElement = this.querySelector('.value-display');
      if (valueElement) {
        if (this.state.isLoading) {
          valueElement.classList.add('animate-pulse');
        } else {
          valueElement.classList.remove('animate-pulse');
        }
      }
    });
  }

  updateValue(value: number | string, isLoading: boolean = false): void {
    this.setState({ value, isLoading });
  }

  getValue(): number | string {
    return this.state.value;
  }

  setLoading(loading: boolean): void {
    this.setState({
      isLoading: loading,
      value: loading ? 'Loading...' : this.state.value
    });
  }

  update(): void {
    // For metrics widget, render handles all updates through observers
    // This method exists to satisfy the abstract Component requirement
  }
}