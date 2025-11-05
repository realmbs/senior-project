/**
 * DOM Builder Utilities
 * Provides type-safe, secure DOM element creation and manipulation
 */

export interface ElementProps {
  className?: string;
  id?: string;
  textContent?: string;
  innerHTML?: string;
  attributes?: Record<string, string>;
  style?: Partial<CSSStyleDeclaration>;
  dataset?: Record<string, string>;
}

export class DOMBuilder {
  /**
   * Create a DOM element with properties and children
   */
  static createElement<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    props?: ElementProps,
    children?: (HTMLElement | Text | string)[]
  ): HTMLElementTagNameMap[K] {
    const element = document.createElement(tag);

    if (props) {
      this.applyProps(element, props);
    }

    if (children) {
      this.appendChildren(element, children);
    }

    return element;
  }

  /**
   * Create a document fragment with multiple elements
   */
  static createFragment(elements: (HTMLElement | Text | string)[]): DocumentFragment {
    const fragment = document.createDocumentFragment();
    elements.forEach(element => {
      if (typeof element === 'string') {
        fragment.appendChild(document.createTextNode(element));
      } else {
        fragment.appendChild(element);
      }
    });
    return fragment;
  }

  /**
   * Create a text node
   */
  static createText(content: string): Text {
    return document.createTextNode(content);
  }

  /**
   * Apply properties to an element
   */
  static applyProps(element: HTMLElement, props: ElementProps): void {
    if (props.className) element.className = props.className;
    if (props.id) element.id = props.id;
    if (props.textContent) element.textContent = props.textContent;
    if (props.innerHTML) element.innerHTML = props.innerHTML;

    if (props.attributes) {
      Object.entries(props.attributes).forEach(([key, value]) => {
        element.setAttribute(key, value);
      });
    }

    if (props.style) {
      Object.assign(element.style, props.style);
    }

    if (props.dataset) {
      Object.entries(props.dataset).forEach(([key, value]) => {
        element.dataset[key] = value;
      });
    }
  }

  /**
   * Append children to an element
   */
  static appendChildren(
    parent: HTMLElement,
    children: (HTMLElement | Text | string)[]
  ): void {
    children.forEach(child => {
      if (typeof child === 'string') {
        parent.appendChild(document.createTextNode(child));
      } else {
        parent.appendChild(child);
      }
    });
  }

  /**
   * Safe text content update
   */
  static updateTextContent(element: HTMLElement | null, text: string): void {
    if (element) {
      element.textContent = text;
    }
  }

  /**
   * Safe attribute update
   */
  static updateAttribute(element: HTMLElement | null, attr: string, value: string): void {
    if (element) {
      element.setAttribute(attr, value);
    }
  }

  /**
   * Safe class manipulation
   */
  static updateClassName(element: HTMLElement | null, className: string): void {
    if (element) {
      element.className = className;
    }
  }

  /**
   * Clear all children from an element
   */
  static clearChildren(element: HTMLElement | null): void {
    if (element) {
      while (element.firstChild) {
        element.removeChild(element.firstChild);
      }
    }
  }

  /**
   * Create an icon element (for Lucide icons)
   */
  static createIcon(iconName: string, className?: string): HTMLElement {
    return this.createElement('i', {
      attributes: { 'data-lucide': iconName },
      className: className || 'w-4 h-4'
    });
  }

  /**
   * Create a badge element
   */
  static createBadge(text: string, variant: 'red' | 'yellow' | 'gray' | 'blue' | 'green' = 'gray'): HTMLElement {
    return this.createElement('span', {
      className: `px-2 py-1 bg-${variant}-500/20 text-${variant}-400 text-xs rounded-full`,
      textContent: text
    });
  }
}