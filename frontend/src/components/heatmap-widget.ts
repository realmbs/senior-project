/**
 * Heatmap Widget Component
 * Displays geographic distribution of threat intelligence using Leaflet heatmap
 */

import { Component } from '../lib/component';
import { DOMBuilder } from '../lib/dom-builder';
import type { ThreatIndicator } from './threat-card';
import { geoCache } from '../lib/geo-cache';

// Use global Leaflet from CDN
declare const L: any;

interface HeatmapWidgetState {
  threats: ThreatIndicator[];
  isLoading: boolean;
  error: string | null;
  totalPoints: number;
  enrichedCount: number;
  isModalOpen: boolean;
}

export class HeatmapWidget extends Component<HeatmapWidgetState> {
  private map: any = null;
  private heatLayer: any = null;
  private modalOverlay: HTMLElement | null = null;

  constructor(element: HTMLElement) {
    super(element, {
      threats: [],
      isLoading: false,
      error: null,
      totalPoints: 0,
      enrichedCount: 0,
      isModalOpen: false
    });

    try {
      this.render();
    } catch (error) {
      console.error('[HeatmapWidget] Constructor error:', error);
      throw error;
    }
  }

  render(): void {
    DOMBuilder.clearChildren(this.element);

    // Main container
    const container = DOMBuilder.createElement('section', {
      className: 'mb-8'
    });

    // Card wrapper - now clickable
    const card = DOMBuilder.createElement('button', {
      id: 'heatmap-toggle-btn',
      className: 'w-full bg-gray-800/50 backdrop-blur-lg rounded-xl border border-gray-700/50 hover:border-blue-500/50 transition-colors cursor-pointer text-left'
    });

    // Header
    const header = this.createHeader();
    card.appendChild(header);

    container.appendChild(card);
    this.element.appendChild(container);

    // Add click handler to open modal
    this.addEventListener(card, 'click', () => this.openModal());

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'p-4 flex items-center justify-between'
    });

    // Title section
    const titleSection = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const iconContainer = DOMBuilder.createElement('div', {
      className: 'p-2 bg-blue-500/20 rounded-lg'
    });
    iconContainer.appendChild(DOMBuilder.createIcon('map', 'w-5 h-5 text-blue-400'));
    titleSection.appendChild(iconContainer);

    const titleText = DOMBuilder.createElement('div');
    const title = DOMBuilder.createElement('h2', {
      className: 'font-medium',
      textContent: 'Threat Heatmap'
    });
    const subtitle = DOMBuilder.createElement('p', {
      id: 'heatmap-subtitle',
      className: 'text-sm text-gray-400',
      textContent: this.state.isLoading ? 'Loading...' : `${this.state.totalPoints} locations`
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

  private createLegend(): HTMLElement {
    const legend = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-2 text-xs text-gray-400'
    });

    const legendLabel = DOMBuilder.createElement('span', {
      textContent: 'Intensity:'
    });
    legend.appendChild(legendLabel);

    // Gradient bar
    const gradientBar = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-1'
    });

    const colors = [
      { label: 'Low', color: 'bg-blue-500' },
      { label: '', color: 'bg-green-500' },
      { label: '', color: 'bg-yellow-500' },
      { label: '', color: 'bg-orange-500' },
      { label: 'High', color: 'bg-red-500' }
    ];

    colors.forEach(({ label, color }) => {
      const colorBox = DOMBuilder.createElement('div', {
        className: `w-3 h-3 rounded-sm ${color}`
      });
      gradientBar.appendChild(colorBox);
      if (label) {
        const labelText = DOMBuilder.createElement('span', {
          className: 'text-gray-400 ml-1',
          textContent: label
        });
        gradientBar.appendChild(labelText);
      }
    });

    legend.appendChild(gradientBar);

    return legend;
  }

  private initializeMap(container: HTMLElement): void {
    try {
      if (this.map) {
        this.map.remove();
      }

      console.log('[HeatmapWidget] Initializing map...');

      // Create map centered on world view
      this.map = L.map(container, {
        center: [20, 0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 18,
        zoomControl: true
      });

      // Add OpenStreetMap tile layer
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
        className: 'map-tiles'
      }).addTo(this.map);

      // Check if heatLayer is available
      if (typeof L.heatLayer === 'function') {
        // Create heatmap layer with custom gradient
        this.heatLayer = L.heatLayer([], {
          radius: 45,          // Increased for larger hotspots
          blur: 60,            // Increased for smoother, more visible gradients
          maxZoom: 8,          // Show heatmap at more zoom levels
          max: 0.5,            // Lower max = higher intensity (colors saturate faster)
          minOpacity: 0.6,     // Increased from 0.4 for more opacity
          gradient: {
            0.0: '#2563eb',  // Vibrant blue (low confidence)
            0.3: '#10b981',  // Vibrant green
            0.5: '#fbbf24',  // Vibrant yellow (medium confidence)
            0.7: '#f97316',  // Vibrant orange
            0.9: '#ef4444'   // Vibrant red (high confidence)
          }
        }).addTo(this.map);
        console.log('[HeatmapWidget] Heatmap layer created via leaflet.heat');
      } else {
        console.error('[HeatmapWidget] L.heatLayer not available - leaflet.heat plugin not loaded');
        console.log('[HeatmapWidget] Available L methods:', Object.keys(L).filter(k => k.includes('heat')));
      }

      console.log('[HeatmapWidget] Map initialized successfully');
    } catch (error) {
      console.error('[HeatmapWidget] Failed to initialize map:', error);
      throw error;
    }
  }

  async update(threats?: ThreatIndicator[]): Promise<void> {
    if (threats) {
      this.setState({ threats, isLoading: true, error: null });
      this.updateLoadingState(true);

      try {
        await this.updateHeatmap(threats);
        this.setState({ isLoading: false });
        this.updateLoadingState(false);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Failed to update heatmap';
        this.setState({ isLoading: false, error: errorMessage });
        this.updateLoadingState(false);
        console.error('[HeatmapWidget] Update error:', error);
      }
    }
  }

  private async updateHeatmap(threats: ThreatIndicator[]): Promise<void> {
    if (!this.heatLayer) {
      console.warn('[HeatmapWidget] Heatmap layer not initialized');
      return;
    }

    // Set loading state
    this.setState({ isLoading: true });
    this.updateStats(0, 0); // This will show "Loading..." in the subtitle

    try {
      // Log IOC type distribution
      const iocTypeCounts = threats.reduce((acc, t) => {
        acc[t.ioc_type] = (acc[t.ioc_type] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      console.log('[HeatmapWidget] IOC type distribution:', iocTypeCounts);

      // Filter both IP and domain threats (Shodan can resolve domains to IPs)
      const ipThreats = threats.filter(t =>
        t.ioc_type === 'ipv4' ||
        t.ioc_type === 'IPv4' ||
        t.ioc_type === 'ipv4-addr' ||
        t.ioc_type === 'ipv6-addr'
      );

      const domainThreats = threats.filter(t =>
        t.ioc_type === 'domain' ||
        t.ioc_type === 'hostname'
      );

      console.log(`[HeatmapWidget] Processing ${ipThreats.length} IP threats + ${domainThreats.length} domain threats (via Shodan)`);

      if (ipThreats.length === 0 && domainThreats.length === 0) {
        this.heatLayer.setLatLngs([]);
        this.setState({ isLoading: false });
        this.updateStats(0, 0);
        return;
      }

      // Build heatmap points from both IPs and domains
      const heatmapPoints: [number, number, number][] = [];
      let totalEnriched = 0;

      // Process direct IP threats
      if (ipThreats.length > 0) {
        const uniqueIps = [...new Set(ipThreats.map(t => t.ioc_value).filter(Boolean))];
        console.log(`[HeatmapWidget] Enriching ${uniqueIps.length} unique IPs...`);

        const ipEnrichedData = await geoCache.batchEnrich(uniqueIps, 10);
        totalEnriched += ipEnrichedData.size;

        ipThreats.forEach(threat => {
          const enriched = ipEnrichedData.get(threat.ioc_value);
          if (enriched && enriched.geolocation) {
            const { latitude, longitude } = enriched.geolocation;
            const intensity = threat.confidence / 100;
            heatmapPoints.push([latitude, longitude, intensity]);
          }
        });
      }

      // Process domain threats (extract IPs from Shodan data)
      if (domainThreats.length > 0) {
        const uniqueDomains = [...new Set(domainThreats.map(t => t.ioc_value).filter(Boolean))];
        // Limit domains to avoid too many API calls (take top 20 by confidence)
        const topDomains = domainThreats
          .sort((a, b) => b.confidence - a.confidence)
          .slice(0, 20)
          .map(t => t.ioc_value)
          .filter(Boolean);

        console.log(`[HeatmapWidget] Enriching ${topDomains.length} domains via Shodan (out of ${uniqueDomains.length} total)...`);

        const domainEnrichedData = await geoCache.batchEnrichDomains(topDomains, 5);
        totalEnriched += domainEnrichedData.size;

        // Log first enriched domain for debugging
        if (domainEnrichedData.size > 0) {
          const firstEntry = Array.from(domainEnrichedData.entries())[0];
          console.log('[HeatmapWidget] Sample enriched domain data:', {
            domain: firstEntry[0],
            hasGeolocation: !!firstEntry[1].geolocation,
            hasShodan: !!firstEntry[1].shodan,
            shodanIp: firstEntry[1].shodan?.ip,
            geolocationData: firstEntry[1].geolocation
          });
        }

        // Extract unique IPs from Shodan data for secondary enrichment
        const shodanIpsToEnrich = new Set<string>();
        const domainToIpMap = new Map<string, string>();

        domainThreats.forEach(threat => {
          const enriched = domainEnrichedData.get(threat.ioc_value);
          if (enriched) {
            // Check if we have geolocation data directly
            if (enriched.geolocation && enriched.geolocation.latitude && enriched.geolocation.longitude) {
              const { latitude, longitude } = enriched.geolocation;
              const intensity = threat.confidence / 100;
              heatmapPoints.push([latitude, longitude, intensity]);
            }
            // Extract Shodan IPs for secondary enrichment
            else if (enriched.shodan && enriched.shodan.ip) {
              shodanIpsToEnrich.add(enriched.shodan.ip);
              domainToIpMap.set(threat.ioc_value, enriched.shodan.ip);
            }
          }
        });

        // Perform secondary enrichment on Shodan IPs
        if (shodanIpsToEnrich.size > 0) {
          console.log(`[HeatmapWidget] Secondary enrichment: ${shodanIpsToEnrich.size} unique IPs from Shodan`);
          const shodanIpEnrichedData = await geoCache.batchEnrich(Array.from(shodanIpsToEnrich), 10);
          totalEnriched += shodanIpEnrichedData.size;

          // Map geolocated IPs back to domains
          domainThreats.forEach(threat => {
            const shodanIp = domainToIpMap.get(threat.ioc_value);
            if (shodanIp) {
              const ipEnriched = shodanIpEnrichedData.get(shodanIp);
              if (ipEnriched && ipEnriched.geolocation) {
                const { latitude, longitude } = ipEnriched.geolocation;
                const intensity = threat.confidence / 100;
                heatmapPoints.push([latitude, longitude, intensity]);
              }
            }
          });
        }
      }

      console.log(`[HeatmapWidget] Rendering ${heatmapPoints.length} heatmap points (${totalEnriched} total enriched)`);

      // Log sample points for debugging
      if (heatmapPoints.length > 0) {
        console.log('[HeatmapWidget] Sample heatmap points:', heatmapPoints.slice(0, 3));
      }

      // Update heatmap layer
      if (this.heatLayer) {
        this.heatLayer.setLatLngs(heatmapPoints);

        // Force layer to redraw
        this.heatLayer.redraw();

        // Bring heatmap to front
        if (this.map) {
          // Remove and re-add to ensure it's on top
          this.heatLayer.addTo(this.map);

          // Force map to redraw
          this.map.invalidateSize();

          // If we have points, fit the map bounds to show them
          if (heatmapPoints.length > 0) {
            const bounds = L.latLngBounds(heatmapPoints.map(p => [p[0], p[1]]));
            this.map.fitBounds(bounds, { padding: [50, 50], maxZoom: 5 });
          }

          // Force another redraw after bounds change
          setTimeout(() => {
            if (this.heatLayer && this.heatLayer.redraw) {
              this.heatLayer.redraw();
            }
          }, 100);
        }

        console.log('[HeatmapWidget] Heatmap layer updated successfully');
      } else {
        console.warn('[HeatmapWidget] Heatmap layer not available for update');
      }

      // Update stats
      this.setState({ isLoading: false });
      this.updateStats(heatmapPoints.length, totalEnriched);
    } catch (error) {
      console.error('[HeatmapWidget] Error updating heatmap:', error);
      this.setState({ isLoading: false, error: 'Failed to load heatmap data' });
      this.updateStats(0, 0);
    }
  }

  private updateLoadingState(isLoading: boolean): void {
    const loadingIndicator = this.querySelector('#heatmap-loading');
    if (loadingIndicator) {
      loadingIndicator.style.display = isLoading ? 'flex' : 'none';
    }

    // Update modal loading state if modal is open
    if (this.state.isModalOpen) {
      const modalLoadingIndicator = document.getElementById('modal-heatmap-loading');
      if (modalLoadingIndicator) {
        modalLoadingIndicator.style.display = isLoading ? 'flex' : 'none';
      }
    }
  }

  private updateStats(totalPoints: number, enrichedCount: number): void {
    this.setState({ totalPoints, enrichedCount });

    // Update subtitle in header
    const subtitle = this.querySelector('#heatmap-subtitle');
    if (subtitle) {
      subtitle.textContent = this.state.isLoading ? 'Loading...' : `${totalPoints} locations`;
    }

    // Update collapsed view stats
    const pointsText = this.querySelector('#heatmap-points-count');
    if (pointsText) {
      pointsText.textContent = `${totalPoints} locations`;
    }

    // Update modal stats if modal is open
    if (this.state.isModalOpen) {
      const modalPointsText = document.getElementById('modal-heatmap-points-count');
      if (modalPointsText) {
        modalPointsText.textContent = `${totalPoints} locations`;
      }
    }
  }

  private openModal(): void {
    if (this.state.isModalOpen) return;

    this.setState({ isModalOpen: true });

    // Create modal overlay
    this.modalOverlay = DOMBuilder.createElement('div', {
      id: 'heatmap-modal',
      className: 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4'
    });

    // Create modal container
    const modal = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 rounded-xl border border-gray-700 w-full max-w-7xl max-h-[90vh] overflow-hidden shadow-2xl flex flex-col'
    });

    // Modal header
    const modalHeader = DOMBuilder.createElement('div', {
      className: 'bg-gray-800 border-b border-gray-700 p-6 flex items-center justify-between'
    });

    const headerTitle = DOMBuilder.createElement('div', {
      className: 'flex items-center space-x-3'
    });
    headerTitle.appendChild(DOMBuilder.createIcon('map', 'w-6 h-6 text-blue-400'));

    const titleContainer = DOMBuilder.createElement('div');
    titleContainer.appendChild(DOMBuilder.createElement('h2', {
      className: 'text-xl font-bold text-white',
      textContent: 'Threat Heatmap'
    }));
    titleContainer.appendChild(DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 mt-1',
      textContent: 'IP-based threat heatmap with confidence-weighted intensity'
    }));
    headerTitle.appendChild(titleContainer);

    // Stats and legend section
    const headerStats = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-6'
    });

    // Stats display
    const statsDisplay = DOMBuilder.createElement('div', {
      id: 'modal-heatmap-stats',
      className: 'flex items-center gap-4 text-sm'
    });

    // Loading indicator
    const loadingIndicator = DOMBuilder.createElement('div', {
      id: 'modal-heatmap-loading',
      className: 'flex items-center gap-2 text-sm text-gray-400',
      style: { display: this.state.isLoading ? 'flex' : 'none' }
    });
    const spinner = DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-4 w-4 border-2 border-blue-400 border-t-transparent'
    });
    loadingIndicator.appendChild(spinner);
    loadingIndicator.appendChild(DOMBuilder.createText('Loading...'));

    const pointsCount = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-2'
    });
    const pointsIcon = DOMBuilder.createIcon('map-pin', 'w-4 h-4 text-blue-400');
    const pointsText = DOMBuilder.createElement('span', {
      id: 'modal-heatmap-points-count',
      className: 'text-gray-300',
      textContent: `${this.state.totalPoints} locations`
    });
    pointsCount.appendChild(pointsIcon);
    pointsCount.appendChild(pointsText);

    statsDisplay.appendChild(loadingIndicator);
    statsDisplay.appendChild(pointsCount);
    headerStats.appendChild(statsDisplay);

    // Legend
    const legend = this.createLegend();
    headerStats.appendChild(legend);

    const closeButton = DOMBuilder.createElement('button', {
      id: 'close-heatmap-modal-btn',
      className: 'p-2 hover:bg-gray-700 rounded-lg transition-colors ml-4'
    });
    closeButton.appendChild(DOMBuilder.createIcon('x', 'w-5 h-5 text-gray-400'));

    modalHeader.appendChild(headerTitle);
    modalHeader.appendChild(headerStats);
    modalHeader.appendChild(closeButton);

    // Modal content (map container)
    const modalContent = DOMBuilder.createElement('div', {
      className: 'flex-1 p-6 overflow-hidden'
    });

    const mapWrapper = DOMBuilder.createElement('div', {
      id: 'modal-map-wrapper',
      className: 'relative rounded-lg overflow-hidden border border-gray-700/30 h-full min-h-[600px]'
    });

    modalContent.appendChild(mapWrapper);

    // Assemble modal
    modal.appendChild(modalHeader);
    modal.appendChild(modalContent);
    this.modalOverlay.appendChild(modal);

    // Add to body
    document.body.appendChild(this.modalOverlay);

    // Refresh icons
    this.refreshIcons();

    // Initialize map after DOM is ready
    setTimeout(() => {
      this.initializeMap(mapWrapper);
      // Update with current threats if available
      if (this.state.threats.length > 0) {
        this.updateHeatmap(this.state.threats);
      }
    }, 100);

    // Close on button click
    closeButton.addEventListener('click', () => this.closeModal());

    // Close on overlay click (not modal content)
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

  private closeModal(): void {
    if (!this.state.isModalOpen) return;

    this.setState({ isModalOpen: false });

    // Clean up map
    if (this.map) {
      this.map.remove();
      this.map = null;
    }
    this.heatLayer = null;

    // Remove modal from DOM
    if (this.modalOverlay) {
      this.modalOverlay.remove();
      this.modalOverlay = null;
    }
  }

  destroy(): void {
    // Close modal if open
    if (this.state.isModalOpen) {
      this.closeModal();
    }

    // Clean up map
    if (this.map) {
      this.map.remove();
      this.map = null;
    }
    this.heatLayer = null;
    super.destroy();
  }
}
