/**
 * ThreatList Component
 * Manages a collection of threat cards with efficient rendering
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import { ThreatCard } from './threat-card.js';
import type { ThreatIndicator } from './threat-card.js';

interface ThreatListState {
  threats: ThreatIndicator[];
  isLoading: boolean;
  maxDisplay: number;
}

export class ThreatList extends Component<ThreatListState> {
  private threatCards: Map<string, ThreatCard> = new Map();
  private onThreatClick?: (ioc: string) => void;

  constructor(
    container: HTMLElement,
    onThreatClick?: (ioc: string) => void,
    maxDisplay: number = 10
  ) {
    super(container, {
      threats: [],
      isLoading: false,
      maxDisplay
    });

    this.onThreatClick = onThreatClick;
    this.setupObservers();
    this.render();
  }

  render(): void {
    const { threats, isLoading, maxDisplay } = this.state;

    // Clear existing content
    DOMBuilder.clearChildren(this.element);

    if (isLoading) {
      this.renderLoading();
      return;
    }

    if (threats.length === 0) {
      this.renderEmpty();
      return;
    }

    // Render threats using DocumentFragment for efficient DOM updates
    const fragment = document.createDocumentFragment();
    const threatsToShow = threats.slice(0, maxDisplay);

    // Clear old threat cards that are no longer needed
    const currentIOCs = new Set(threatsToShow.map(t => t.ioc_value));
    for (const [ioc, card] of this.threatCards) {
      if (!currentIOCs.has(ioc)) {
        card.destroy();
        this.threatCards.delete(ioc);
      }
    }

    // Create or update threat cards
    threatsToShow.forEach(threat => {
      const existingCard = this.threatCards.get(threat.ioc_value);

      if (existingCard) {
        // Update existing card
        existingCard.update(threat);
        fragment.appendChild(existingCard.getElement());
      } else {
        // Create new card
        const newCard = new ThreatCard(threat, this.onThreatClick);
        this.threatCards.set(threat.ioc_value, newCard);
        fragment.appendChild(newCard.getElement());
      }
    });

    // Add fragment to container
    this.element.appendChild(fragment);

    // Refresh Lucide icons after DOM update
    this.refreshIcons();
  }

  private renderLoading(): void {
    const loadingContainer = DOMBuilder.createElement('div', {
      className: 'flex items-center justify-center py-8'
    });

    const spinner = DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-8 w-8 border-b-2 border-blue-400'
    });

    loadingContainer.appendChild(spinner);
    this.element.appendChild(loadingContainer);
  }

  private renderEmpty(): void {
    const emptyContainer = DOMBuilder.createElement('div', {
      className: 'text-center py-8 text-gray-400'
    });

    const icon = DOMBuilder.createIcon('inbox', 'w-12 h-12 mx-auto mb-4 opacity-50');
    const message = DOMBuilder.createElement('p', {
      textContent: 'No threats found'
    });

    emptyContainer.appendChild(icon);
    emptyContainer.appendChild(message);
    this.element.appendChild(emptyContainer);

    this.refreshIcons();
  }

  private setupObservers(): void {
    this.observe('threats', () => this.render());
    this.observe('isLoading', () => this.render());
    this.observe('maxDisplay', () => this.render());
  }

  updateThreats(threats: ThreatIndicator[]): void {
    this.setState({ threats, isLoading: false });
  }

  addThreat(threat: ThreatIndicator): void {
    const currentThreats = [...this.state.threats];
    // Add to beginning of list (most recent first)
    currentThreats.unshift(threat);
    this.setState({ threats: currentThreats });
  }

  removeThreat(iocValue: string): void {
    const filteredThreats = this.state.threats.filter(t => t.ioc_value !== iocValue);
    this.setState({ threats: filteredThreats });

    // Clean up threat card
    const card = this.threatCards.get(iocValue);
    if (card) {
      card.destroy();
      this.threatCards.delete(iocValue);
    }
  }

  setLoading(loading: boolean): void {
    this.setState({ isLoading: loading });
  }

  getThreats(): ThreatIndicator[] {
    return [...this.state.threats];
  }

  getThreatsCount(): number {
    return this.state.threats.length;
  }

  setMaxDisplay(max: number): void {
    this.setState({ maxDisplay: max });
  }

  update(threats?: ThreatIndicator[]): void {
    if (threats) {
      this.updateThreats(threats);
    }
  }

  destroy(): void {
    // Clean up all threat cards
    for (const card of this.threatCards.values()) {
      card.destroy();
    }
    this.threatCards.clear();

    // Call parent destroy
    super.destroy();
  }
}