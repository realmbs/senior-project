/**
 * Settings Modal
 * Modal for testing API endpoints and triggering collection
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';

interface SettingsModalState {
  isOpen: boolean;
}

export class SettingsModal extends Component<SettingsModalState> {
  private modalOverlay: HTMLElement | null = null;
  private onTriggerCollection: () => void;
  private onTestSearch: () => void;
  private onTestEnrich: () => void;

  constructor(
    element: HTMLElement,
    callbacks: {
      onTriggerCollection: () => void;
      onTestSearch: () => void;
      onTestEnrich: () => void;
    }
  ) {
    super(element, {
      isOpen: false
    });
    this.onTriggerCollection = callbacks.onTriggerCollection;
    this.onTestSearch = callbacks.onTestSearch;
    this.onTestEnrich = callbacks.onTestEnrich;
  }

  render(): void {
    // Modal is rendered dynamically in openModal()
  }

  update(): void {
    // No updates needed for settings modal
  }

  /**
   * Open the modal
   */
  openModal(): void {
    if (this.state.isOpen) return;

    this.setState({ isOpen: true });

    // Create modal overlay
    this.modalOverlay = DOMBuilder.createElement('div', {
      id: 'settings-modal',
      className: 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    });

    // Create modal container
    const modal = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 rounded-xl border border-gray-700 w-full max-w-2xl overflow-hidden shadow-2xl'
    });

    // Modal header
    const modalHeader = this.createModalHeader();
    modal.appendChild(modalHeader);

    // Modal content
    const modalContent = DOMBuilder.createElement('div', {
      className: 'p-6 space-y-4'
    });

    // Add sections
    modalContent.appendChild(this.createCollectionSection());
    modalContent.appendChild(this.createTestingSection());

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

    // Setup event listeners
    this.setupEventListeners();
  }

  /**
   * Close the modal
   */
  closeModal(): void {
    if (!this.state.isOpen) return;

    this.setState({ isOpen: false });

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
    headerTitle.appendChild(DOMBuilder.createIcon('settings', 'w-6 h-6 text-blue-400'));

    const titleContainer = DOMBuilder.createElement('div');
    titleContainer.appendChild(DOMBuilder.createElement('h2', {
      className: 'text-xl font-bold text-white',
      textContent: 'Settings & Testing'
    }));
    titleContainer.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mt-1',
      textContent: 'Trigger data collection and test API endpoints'
    }));
    headerTitle.appendChild(titleContainer);

    // Close button
    const closeButton = DOMBuilder.createElement('button', {
      id: 'close-settings-modal-btn',
      className: 'p-2 hover:bg-gray-700 rounded-lg transition-colors'
    });
    closeButton.appendChild(DOMBuilder.createIcon('x', 'w-5 h-5 text-gray-400'));

    header.appendChild(headerTitle);
    header.appendChild(closeButton);

    return header;
  }

  /**
   * Create collection section
   */
  private createCollectionSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
    });

    // Section title
    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-4 flex items-center space-x-2'
    });
    title.appendChild(DOMBuilder.createIcon('database', 'w-5 h-5 text-purple-400'));
    const titleText = DOMBuilder.createElement('span', {
      textContent: 'Data Collection'
    });
    title.appendChild(titleText);
    section.appendChild(title);

    // Description
    const description = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mb-4',
      textContent: 'Manually trigger data collection from OTX and URLhaus threat intelligence sources.'
    });
    section.appendChild(description);

    // Trigger button
    const triggerButton = DOMBuilder.createElement('button', {
      id: 'modal-trigger-collection-btn',
      className: 'w-full bg-purple-600 hover:bg-purple-700 text-white px-4 py-3 rounded-lg transition-colors flex items-center justify-center space-x-2'
    });
    triggerButton.appendChild(DOMBuilder.createIcon('play', 'w-5 h-5'));
    const buttonText = DOMBuilder.createElement('span', {
      textContent: 'Trigger Collection'
    });
    triggerButton.appendChild(buttonText);
    section.appendChild(triggerButton);

    return section;
  }

  /**
   * Create testing section
   */
  private createTestingSection(): HTMLElement {
    const section = DOMBuilder.createElement('div', {
      className: 'bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 p-6'
    });

    // Section title
    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white mb-4 flex items-center space-x-2'
    });
    title.appendChild(DOMBuilder.createIcon('flask-conical', 'w-5 h-5 text-green-400'));
    const titleText = DOMBuilder.createElement('span', {
      textContent: 'API Endpoint Testing'
    });
    title.appendChild(titleText);
    section.appendChild(title);

    // Description
    const description = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mb-4',
      textContent: 'Test individual API endpoints to verify connectivity and functionality.'
    });
    section.appendChild(description);

    // Button container
    const buttonContainer = DOMBuilder.createElement('div', {
      className: 'space-y-3'
    });

    // Test Search button
    const testSearchButton = DOMBuilder.createElement('button', {
      id: 'modal-test-search-btn',
      className: 'w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-3 rounded-lg transition-colors flex items-center justify-center space-x-2'
    });
    testSearchButton.appendChild(DOMBuilder.createIcon('search', 'w-5 h-5'));
    const searchButtonText = DOMBuilder.createElement('span', {
      textContent: 'Test Search Endpoint'
    });
    testSearchButton.appendChild(searchButtonText);
    buttonContainer.appendChild(testSearchButton);

    // Test Enrich button
    const testEnrichButton = DOMBuilder.createElement('button', {
      id: 'modal-test-enrich-btn',
      className: 'w-full bg-green-600 hover:bg-green-700 text-white px-4 py-3 rounded-lg transition-colors flex items-center justify-center space-x-2'
    });
    testEnrichButton.appendChild(DOMBuilder.createIcon('sparkles', 'w-5 h-5'));
    const enrichButtonText = DOMBuilder.createElement('span', {
      textContent: 'Test Enrich Endpoint'
    });
    testEnrichButton.appendChild(enrichButtonText);
    buttonContainer.appendChild(testEnrichButton);

    section.appendChild(buttonContainer);

    return section;
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    if (!this.modalOverlay) return;

    // Close button
    const closeButton = this.modalOverlay.querySelector('#close-settings-modal-btn');
    if (closeButton) {
      closeButton.addEventListener('click', () => this.closeModal());
    }

    // Trigger collection button
    const triggerButton = this.modalOverlay.querySelector('#modal-trigger-collection-btn');
    if (triggerButton) {
      triggerButton.addEventListener('click', () => {
        this.onTriggerCollection();
        this.closeModal();
      });
    }

    // Test search button
    const testSearchButton = this.modalOverlay.querySelector('#modal-test-search-btn');
    if (testSearchButton) {
      testSearchButton.addEventListener('click', () => {
        this.onTestSearch();
        this.closeModal();
      });
    }

    // Test enrich button
    const testEnrichButton = this.modalOverlay.querySelector('#modal-test-enrich-btn');
    if (testEnrichButton) {
      testEnrichButton.addEventListener('click', () => {
        this.onTestEnrich();
        this.closeModal();
      });
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
}
