/**
 * Visual Analysis Trigger Widget
 * Displays a button that opens the analytics modal
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';

interface VisualAnalysisTriggerState {
  isDisabled: boolean;
}

export class VisualAnalysisTriggerWidget extends Component<VisualAnalysisTriggerState> {
  private onOpenModal: (() => void) | null = null;

  constructor(element: HTMLElement, onOpenModal: () => void) {
    super(element, {
      isDisabled: false
    });

    this.onOpenModal = onOpenModal;
    this.render();
  }

  render(): void {
    DOMBuilder.clearChildren(this.element);

    // Main container
    const container = DOMBuilder.createElement('section', {
      className: 'mb-8'
    });

    // Card wrapper - clickable button
    const card = DOMBuilder.createElement('button', {
      id: 'analytics-toggle-btn',
      className: 'w-full bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 hover:border-purple-500/50 transition-colors cursor-pointer text-left'
    });

    // Header
    const header = this.createHeader();
    card.appendChild(header);

    container.appendChild(card);
    this.element.appendChild(container);

    // Add click handler to open modal
    this.addEventListener(card, 'click', () => {
      if (this.onOpenModal && !this.state.isDisabled) {
        this.onOpenModal();
      }
    });

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'p-6 flex items-center justify-between'
    });

    // Title section
    const titleSection = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('bar-chart-2', 'w-6 h-6 text-purple-400');
    titleSection.appendChild(icon);

    const titleText = DOMBuilder.createElement('div');
    const title = DOMBuilder.createElement('h2', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Threat Analytics & Trends'
    });
    const subtitle = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mt-1',
      textContent: 'Click to view time-series analysis and insights'
    });
    titleText.appendChild(title);
    titleText.appendChild(subtitle);
    titleSection.appendChild(titleText);

    header.appendChild(titleSection);

    // Right section - expand icon
    const expandIcon = DOMBuilder.createIcon('chevron-right', 'w-5 h-5 text-gray-400');
    header.appendChild(expandIcon);

    return header;
  }

  update(data?: any): void {
    // Optional: Update state if needed (e.g., disable button during loading)
    if (data && typeof data.isDisabled === 'boolean') {
      this.setState({ isDisabled: data.isDisabled });

      // Update button state
      const button = this.querySelector('#analytics-toggle-btn');
      if (button) {
        button.classList.toggle('opacity-50', data.isDisabled);
        button.classList.toggle('cursor-not-allowed', data.isDisabled);
        button.classList.toggle('cursor-pointer', !data.isDisabled);
      }
    }
  }
}
