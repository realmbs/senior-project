/**
 * Geographic Risk Assessment Widget
 * Displays country-based threat aggregation with risk scoring
 */

import { Component } from '../lib/component.js';
import { DOMBuilder } from '../lib/dom-builder.js';
import type { ThreatIndicator } from './threat-card.js';
import { geoCache } from '../lib/geo-cache.js';

interface GeographicRiskState {
  threats: ThreatIndicator[];
  isLoading: boolean;
  isEnriching: boolean;
  enrichmentComplete: boolean;
}

interface CountryRiskData {
  country: string;
  countryCode: string;
  threatCount: number;
  avgConfidence: number;
  highRiskCount: number;
  iocTypes: string[];
  riskScore: number;
}

export class GeographicRiskWidget extends Component<GeographicRiskState> {
  constructor(element: HTMLElement) {
    const container = DOMBuilder.createElement('div', {
      className: 'w-full'
    });

    element.appendChild(container);

    super(container, {
      threats: [],
      isLoading: false,
      isEnriching: false,
      enrichmentComplete: false
    });

    this.render();
  }

  render(): void {
    DOMBuilder.clearChildren(this.element);

    // Header section
    const header = this.createHeader();
    this.element.appendChild(header);

    // Main content
    if (this.state.isEnriching) {
      const loadingState = this.createLoadingState();
      this.element.appendChild(loadingState);
    } else if (this.state.enrichmentComplete) {
      const riskData = this.aggregateGeographicRisk();

      if (riskData.length === 0) {
        const emptyState = this.createEmptyState();
        this.element.appendChild(emptyState);
      } else {
        // Stats cards
        const statsCards = this.createStatsCards(riskData);
        this.element.appendChild(statsCards);

        // Risk table
        const riskTable = this.createRiskTable(riskData);
        this.element.appendChild(riskTable);
      }
    } else {
      // Not yet enriched - show message
      const pendingState = this.createPendingState();
      this.element.appendChild(pendingState);
    }

    this.refreshIcons();
  }

  private createHeader(): HTMLElement {
    const header = DOMBuilder.createElement('div', {
      className: 'flex items-center gap-3'
    });

    const icon = DOMBuilder.createIcon('map-pin', 'w-5 h-5 text-orange-400');
    header.appendChild(icon);

    const title = DOMBuilder.createElement('h3', {
      className: 'text-lg font-semibold text-white',
      textContent: 'Geographic Risk'
    });
    header.appendChild(title);

    return header;
  }

  private createLoadingState(): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'mt-4 flex flex-col items-center justify-center py-12 bg-gray-700/30 rounded-lg border border-gray-600/30'
    });

    const spinner = DOMBuilder.createElement('div', {
      className: 'animate-spin rounded-full h-8 w-8 border-2 border-orange-400 border-t-transparent mb-4'
    });
    container.appendChild(spinner);

    const text = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'Enriching geolocation data...'
    });
    container.appendChild(text);

    return container;
  }

  private createPendingState(): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'mt-4 flex flex-col items-center justify-center py-12 bg-gray-700/30 rounded-lg border border-gray-600/30'
    });

    const icon = DOMBuilder.createIcon('globe', 'w-8 h-8 text-gray-500 mb-3');
    container.appendChild(icon);

    const text = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400',
      textContent: 'Geolocation enrichment pending...'
    });
    container.appendChild(text);

    return container;
  }

  private createEmptyState(): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'mt-4 flex flex-col items-center justify-center py-12 bg-gray-700/30 rounded-lg border border-gray-600/30'
    });

    const icon = DOMBuilder.createIcon('map-pin-off', 'w-8 h-8 text-gray-500 mb-3');
    container.appendChild(icon);

    const text = DOMBuilder.createElement('p', {
      className: 'text-sm text-gray-400 text-center px-4',
      textContent: 'No geolocation data available. Geographic data requires Shodan enrichment.'
    });
    container.appendChild(text);

    return container;
  }

  private createStatsCards(riskData: CountryRiskData[]): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'mt-4 grid grid-cols-1 sm:grid-cols-3 gap-3'
    });

    // Total countries
    const totalCountries = riskData.length;
    const totalCard = this.createStatCard(
      'Countries Detected',
      totalCountries.toString(),
      'text-blue-400',
      'globe'
    );
    container.appendChild(totalCard);

    // Highest risk country
    const highestRisk = riskData[0]; // Already sorted by risk score
    const highestRiskCard = this.createStatCard(
      'Highest Risk',
      highestRisk ? highestRisk.country : 'N/A',
      'text-red-400',
      'alert-triangle'
    );
    container.appendChild(highestRiskCard);

    // Geographic diversity (unique IOC types across all countries)
    const allIOCTypes = new Set<string>();
    riskData.forEach(country => {
      country.iocTypes.forEach(type => allIOCTypes.add(type));
    });

    const diversityCard = this.createStatCard(
      'IOC Diversity',
      `${allIOCTypes.size} types`,
      'text-purple-400',
      'layers'
    );
    container.appendChild(diversityCard);

    return container;
  }

  private createStatCard(label: string, value: string, valueClass: string, iconName: string): HTMLElement {
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
      className: `text-xl font-bold ${valueClass}`,
      textContent: value
    });
    card.appendChild(valueEl);

    return card;
  }

  private createRiskTable(riskData: CountryRiskData[]): HTMLElement {
    const container = DOMBuilder.createElement('div', {
      className: 'mt-4'
    });

    const tableTitle = DOMBuilder.createElement('h4', {
      className: 'text-sm font-semibold text-gray-400 mb-3',
      textContent: 'Top 10 Countries by Risk Score'
    });
    container.appendChild(tableTitle);

    const tableWrapper = DOMBuilder.createElement('div', {
      className: 'bg-gray-700/30 rounded-lg border border-gray-600/30 overflow-hidden'
    });

    const table = DOMBuilder.createElement('table', {
      className: 'w-full text-sm'
    });

    // Table header
    const thead = DOMBuilder.createElement('thead', {
      className: 'bg-gray-800/50 border-b border-gray-600/30'
    });

    const headerRow = DOMBuilder.createElement('tr');
    const headers = ['Country', 'Threats', 'Avg Conf', 'High Risk', 'Risk Score'];

    headers.forEach(headerText => {
      const th = DOMBuilder.createElement('th', {
        className: 'px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider',
        textContent: headerText
      });
      headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    // Table body
    const tbody = DOMBuilder.createElement('tbody', {
      className: 'divide-y divide-gray-600/30'
    });

    // Show top 10 countries
    const top10 = riskData.slice(0, 10);

    top10.forEach((country, index) => {
      const row = DOMBuilder.createElement('tr', {
        className: index % 2 === 0 ? 'bg-gray-700/20' : 'bg-gray-700/10'
      });

      // Country
      const countryCell = DOMBuilder.createElement('td', {
        className: 'px-4 py-3 text-white font-medium'
      });

      const countryContainer = DOMBuilder.createElement('div', {
        className: 'flex items-center gap-2'
      });

      const flag = DOMBuilder.createElement('span', {
        className: 'text-base',
        textContent: this.getCountryFlag(country.countryCode)
      });
      countryContainer.appendChild(flag);

      const countryName = DOMBuilder.createElement('span', {
        textContent: country.country
      });
      countryContainer.appendChild(countryName);

      countryCell.appendChild(countryContainer);
      row.appendChild(countryCell);

      // Threat count
      const threatCell = DOMBuilder.createElement('td', {
        className: 'px-4 py-3 text-gray-300',
        textContent: country.threatCount.toString()
      });
      row.appendChild(threatCell);

      // Average confidence
      const confCell = DOMBuilder.createElement('td', {
        className: 'px-4 py-3'
      });

      const confBadge = DOMBuilder.createElement('span', {
        className: this.getConfidenceBadgeClass(country.avgConfidence),
        textContent: `${country.avgConfidence}%`
      });
      confCell.appendChild(confBadge);
      row.appendChild(confCell);

      // High risk count
      const highRiskCell = DOMBuilder.createElement('td', {
        className: 'px-4 py-3 text-red-400 font-semibold',
        textContent: country.highRiskCount.toString()
      });
      row.appendChild(highRiskCell);

      // Risk score
      const riskCell = DOMBuilder.createElement('td', {
        className: 'px-4 py-3'
      });

      const riskBadge = DOMBuilder.createElement('span', {
        className: this.getRiskScoreBadgeClass(country.riskScore),
        textContent: country.riskScore.toFixed(1)
      });
      riskCell.appendChild(riskBadge);
      row.appendChild(riskCell);

      tbody.appendChild(row);
    });

    table.appendChild(tbody);
    tableWrapper.appendChild(table);
    container.appendChild(tableWrapper);

    return container;
  }

  private getConfidenceBadgeClass(confidence: number): string {
    if (confidence >= 80) {
      return 'px-2 py-1 rounded bg-red-500/20 text-red-400 text-xs font-medium';
    } else if (confidence >= 60) {
      return 'px-2 py-1 rounded bg-yellow-500/20 text-yellow-400 text-xs font-medium';
    } else {
      return 'px-2 py-1 rounded bg-blue-500/20 text-blue-400 text-xs font-medium';
    }
  }

  private getRiskScoreBadgeClass(riskScore: number): string {
    if (riskScore > 50) {
      return 'px-2 py-1 rounded bg-red-500/20 text-red-400 text-xs font-bold';
    } else if (riskScore > 25) {
      return 'px-2 py-1 rounded bg-orange-500/20 text-orange-400 text-xs font-bold';
    } else {
      return 'px-2 py-1 rounded bg-yellow-500/20 text-yellow-400 text-xs font-bold';
    }
  }

  private getCountryFlag(countryCode: string): string {
    if (!countryCode || countryCode.length !== 2) return '🌐';

    // Convert country code to regional indicator symbols (flag emoji)
    const codePoints = countryCode.toUpperCase().split('').map(char =>
      127397 + char.charCodeAt(0)
    );
    return String.fromCodePoint(...codePoints);
  }

  private aggregateGeographicRisk(): CountryRiskData[] {
    const { threats } = this.state;
    const countryMap = new Map<string, {
      threats: ThreatIndicator[];
      totalConfidence: number;
      iocTypes: Set<string>;
      countryCode: string;
    }>();

    // Aggregate threats by country using GeoCache
    threats.forEach(threat => {
      const enriched = geoCache.get(threat.ioc_value);
      if (!enriched) return;

      // Extract country info (try geolocation first, then Shodan)
      let country: string | undefined;
      let countryCode: string | undefined;

      if (enriched.geolocation) {
        country = enriched.geolocation.country;
        countryCode = enriched.geolocation.country_code;
      } else if (enriched.shodan) {
        country = enriched.shodan.country_name;
        countryCode = enriched.shodan.country_code;
      }

      if (!country) return;

      if (!countryMap.has(country)) {
        countryMap.set(country, {
          threats: [],
          totalConfidence: 0,
          iocTypes: new Set(),
          countryCode: countryCode || ''
        });
      }

      const data = countryMap.get(country)!;
      data.threats.push(threat);
      data.totalConfidence += threat.confidence || 0;
      data.iocTypes.add(threat.ioc_type);
    });

    // Calculate risk scores and create final data structure
    const riskData: CountryRiskData[] = Array.from(countryMap.entries())
      .map(([country, data]) => {
        const threatCount = data.threats.length;
        const avgConfidence = Math.round(data.totalConfidence / threatCount);
        const highRiskCount = data.threats.filter(t => (t.confidence || 0) >= 80).length;

        // Risk score formula: (threat count × average confidence) / 100
        // This gives higher weight to countries with both many threats AND high confidence
        const riskScore = (threatCount * avgConfidence) / 100;

        return {
          country,
          countryCode: data.countryCode,
          threatCount,
          avgConfidence,
          highRiskCount,
          iocTypes: Array.from(data.iocTypes),
          riskScore
        };
      })
      .sort((a, b) => b.riskScore - a.riskScore); // Sort by risk score descending

    return riskData;
  }

  async update(threats?: ThreatIndicator[]): Promise<void> {
    if (threats) {
      this.setState({ threats, isEnriching: true });
      this.render();

      // Enrich threats with geolocation data
      await this.enrichThreats(threats);

      this.setState({ isEnriching: false, enrichmentComplete: true });
      this.render();
    }
  }

  private async enrichThreats(threats: ThreatIndicator[]): Promise<void> {
    // Separate IPs and domains
    const ips = threats
      .filter(t => t.ioc_type === 'ipv4' || t.ioc_type === 'ipv6')
      .map(t => t.ioc_value);

    const domains = threats
      .filter(t => t.ioc_type === 'domain' || t.ioc_type === 'hostname')
      .map(t => t.ioc_value)
      .slice(0, 20); // Limit domains to top 20 to avoid excessive API calls

    console.log(`[GeographicRiskWidget] Enriching ${ips.length} IPs and ${domains.length} domains`);

    try {
      // Batch enrich IPs and domains
      const [ipResults, domainResults] = await Promise.all([
        geoCache.batchEnrich(ips, 10),
        geoCache.batchEnrichDomains(domains, 5)
      ]);

      console.log(`[GeographicRiskWidget] Enriched ${ipResults.size} IPs and ${domainResults.size} domains`);
    } catch (error) {
      console.error('[GeographicRiskWidget] Enrichment failed:', error);
    }
  }
}
