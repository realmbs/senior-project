/**
 * Base Component Class
 * Provides reactive state management and lifecycle methods
 */

export interface ComponentState {
  [key: string]: any;
}

export abstract class Component<T extends ComponentState = ComponentState> {
  protected element: HTMLElement;
  protected state: T;
  protected observers: Map<string, (() => void)[]> = new Map();
  protected eventListeners: Array<{
    element: HTMLElement | Window | Document;
    type: string;
    listener: EventListener;
  }> = [];

  constructor(element: HTMLElement, initialState: T) {
    this.element = element;
    this.state = { ...initialState };
  }

  /**
   * Update component state and trigger reactive updates
   */
  protected setState(updates: Partial<T>): void {
    const oldState = { ...this.state };
    this.state = { ...this.state, ...updates };

    // Trigger observers for changed keys
    Object.keys(updates).forEach(key => {
      if (oldState[key] !== this.state[key]) {
        this.notifyObservers(key);
      }
    });
  }

  /**
   * Get current state value
   */
  protected getState<K extends keyof T>(key: K): T[K] {
    return this.state[key];
  }

  /**
   * Subscribe to state changes
   */
  protected observe(key: string, callback: () => void): void {
    if (!this.observers.has(key)) {
      this.observers.set(key, []);
    }
    this.observers.get(key)!.push(callback);
  }

  /**
   * Notify observers of state changes
   */
  private notifyObservers(key: string): void {
    const callbacks = this.observers.get(key);
    if (callbacks) {
      callbacks.forEach(callback => callback());
    }
  }

  /**
   * Add event listener with automatic cleanup tracking
   */
  protected addEventListener<K extends keyof HTMLElementEventMap>(
    element: HTMLElement,
    type: K,
    listener: (this: HTMLElement, ev: HTMLElementEventMap[K]) => void
  ): void;
  protected addEventListener<K extends keyof WindowEventMap>(
    element: Window,
    type: K,
    listener: (this: Window, ev: WindowEventMap[K]) => void
  ): void;
  protected addEventListener<K extends keyof DocumentEventMap>(
    element: Document,
    type: K,
    listener: (this: Document, ev: DocumentEventMap[K]) => void
  ): void;
  protected addEventListener(
    element: HTMLElement | Window | Document,
    type: string,
    listener: EventListener
  ): void {
    element.addEventListener(type, listener);
    this.eventListeners.push({ element, type, listener });
  }

  /**
   * Remove specific event listener
   */
  protected removeEventListener(
    element: HTMLElement | Window | Document,
    type: string,
    listener: EventListener
  ): void {
    element.removeEventListener(type, listener);
    this.eventListeners = this.eventListeners.filter(
      item => !(item.element === element && item.type === type && item.listener === listener)
    );
  }

  /**
   * Get the root element
   */
  getElement(): HTMLElement {
    return this.element;
  }

  /**
   * Find child element by selector
   */
  protected querySelector<T extends HTMLElement = HTMLElement>(selector: string): T | null {
    return this.element.querySelector(selector) as T | null;
  }

  /**
   * Find child elements by selector
   */
  protected querySelectorAll<T extends HTMLElement = HTMLElement>(selector: string): NodeListOf<T> {
    return this.element.querySelectorAll(selector) as NodeListOf<T>;
  }

  /**
   * Update element text content safely
   */
  protected updateText(selector: string, text: string): void {
    const element = this.querySelector(selector);
    if (element) {
      element.textContent = text;
    }
  }

  /**
   * Update element attribute safely
   */
  protected updateAttribute(selector: string, attr: string, value: string): void {
    const element = this.querySelector(selector);
    if (element) {
      element.setAttribute(attr, value);
    }
  }

  /**
   * Update element class safely
   */
  protected updateClass(selector: string, className: string): void {
    const element = this.querySelector(selector);
    if (element) {
      element.className = className;
    }
  }

  /**
   * Show/hide element
   */
  protected toggleVisibility(selector: string, visible: boolean): void {
    const element = this.querySelector(selector);
    if (element) {
      element.style.display = visible ? '' : 'none';
    }
  }

  /**
   * Abstract method for rendering component
   */
  abstract render(): void;

  /**
   * Abstract method for component updates
   */
  abstract update(data?: any): void;

  /**
   * Cleanup method - removes all event listeners and observers
   */
  destroy(): void {
    // Remove all event listeners
    this.eventListeners.forEach(({ element, type, listener }) => {
      element.removeEventListener(type, listener);
    });
    this.eventListeners = [];

    // Clear all observers
    this.observers.clear();

    // Remove element from DOM if it has a parent
    if (this.element.parentNode) {
      this.element.parentNode.removeChild(this.element);
    }
  }

  /**
   * Refresh Lucide icons within component
   */
  protected refreshIcons(): void {
    if (window.lucide) {
      // Only refresh icons within this component's element
      window.lucide.createIcons({
        icons: {},
        nameAttr: 'data-lucide',
        nodes: this.element.querySelectorAll('[data-lucide]')
      });
    }
  }
}