/**
 * Analytics Utilities
 * Data aggregation and processing functions for threat intelligence analytics
 */

import type { ThreatIndicator } from '../components/threat-card.js';

export type TimePeriod = 'hourly' | 'daily' | 'weekly';

export interface TimeSeriesData {
  labels: string[];
  values: number[];
}

export interface SourceStats {
  source: string;
  total: number;
  highConfidence: number;
  avgConfidence: number;
  iocTypes: string[];
  recentActivity: number;
}

export interface CollectionMetric {
  timestamp: string;
  source: string;
  count: number;
  duration?: number;
  status: 'success' | 'warning' | 'error';
}

/**
 * Get ISO week number from date
 */
function getWeekNumber(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
}

/**
 * Format date label based on time period
 */
function formatDateLabel(dateKey: string, period: TimePeriod): string {
  if (period === 'hourly') {
    // "2025-11-05T14" -> "Nov 5, 2pm"
    // Parse as UTC to match how buckets were generated
    const date = new Date(dateKey + ':00:00.000Z');
    const hour = date.getUTCHours();
    const ampm = hour >= 12 ? 'pm' : 'am';
    const hour12 = hour % 12 || 12;
    const month = date.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
    const day = date.getUTCDate();
    return `${month} ${day}, ${hour12}${ampm}`;
  } else if (period === 'daily') {
    // "2025-11-05" -> "Nov 5"
    // Parse as UTC to match how buckets were generated
    const date = new Date(dateKey + 'T00:00:00.000Z');
    const month = date.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
    const day = date.getUTCDate();
    return `${month} ${day}`;
  } else {
    // "2025-W45" -> "Week 45"
    const weekNum = dateKey.split('-W')[1];
    return `Week ${weekNum}`;
  }
}

/**
 * Get time range for period
 */
function getTimeRange(period: TimePeriod): { start: Date; bucketCount: number } {
  const now = new Date();
  let start: Date;
  let bucketCount: number;

  switch (period) {
    case 'hourly':
      // Last 24 hours
      start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      bucketCount = 24;
      break;
    case 'daily':
      // Last 7 days
      start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      bucketCount = 7;
      break;
    case 'weekly':
      // Last 12 weeks
      start = new Date(now.getTime() - 12 * 7 * 24 * 60 * 60 * 1000);
      bucketCount = 12;
      break;
  }

  return { start, bucketCount };
}

/**
 * Generate time buckets for the given period
 */
function generateTimeBuckets(period: TimePeriod): string[] {
  const { start, bucketCount } = getTimeRange(period);
  const buckets: string[] = [];
  const current = new Date(start);

  for (let i = 0; i < bucketCount; i++) {
    let key: string;

    switch (period) {
      case 'hourly':
        key = current.toISOString().slice(0, 13); // "2025-11-05T14"
        current.setUTCHours(current.getUTCHours() + 1);
        break;
      case 'daily':
        key = current.toISOString().slice(0, 10); // "2025-11-05"
        current.setUTCDate(current.getUTCDate() + 1);
        break;
      case 'weekly':
        const weekNum = getWeekNumber(current);
        key = `${current.getUTCFullYear()}-W${weekNum.toString().padStart(2, '0')}`;
        current.setUTCDate(current.getUTCDate() + 7);
        break;
      default:
        key = '';
    }

    buckets.push(key);
  }

  return buckets;
}

/**
 * Aggregate threats by time period
 */
export function aggregateByTime(threats: ThreatIndicator[], period: TimePeriod): TimeSeriesData {
  const { start } = getTimeRange(period);
  const bucketMap = new Map<string, number>();

  // Initialize all buckets with 0
  const timeBuckets = generateTimeBuckets(period);
  timeBuckets.forEach(bucket => bucketMap.set(bucket, 0));

  // Count threats in each bucket
  threats.forEach(threat => {
    // Validate created_at field
    if (!threat.created_at) {
      console.warn('[analytics-utils] Skipping threat with missing created_at:', threat);
      return;
    }

    const date = new Date(threat.created_at);

    // Check if date is valid
    if (isNaN(date.getTime())) {
      console.warn('[analytics-utils] Invalid date for threat:', threat.created_at);
      return;
    }

    // Skip threats outside the time range
    if (date < start) return;

    let key: string;

    switch (period) {
      case 'hourly':
        // Use UTC to match bucket generation
        key = date.toISOString().slice(0, 13); // "2025-11-05T14"
        break;
      case 'daily':
        // Use UTC to match bucket generation
        key = date.toISOString().slice(0, 10); // "2025-11-05"
        break;
      case 'weekly':
        // Use UTC for week calculation
        const weekNum = getWeekNumber(date);
        key = `${date.getUTCFullYear()}-W${weekNum.toString().padStart(2, '0')}`;
        break;
      default:
        return;
    }

    if (bucketMap.has(key)) {
      bucketMap.set(key, bucketMap.get(key)! + 1);
    }
  });

  // Convert to arrays maintaining time order
  const labels = timeBuckets.map(key => formatDateLabel(key, period));
  const values = timeBuckets.map(key => bucketMap.get(key) || 0);

  return { labels, values };
}

/**
 * Compare source effectiveness
 */
export function compareSourceEffectiveness(threats: ThreatIndicator[]): SourceStats[] {
  const sourceStatsMap = new Map<string, {
    total: number;
    highConfidence: number;
    totalConfidence: number;
    iocTypes: Set<string>;
    recentActivity: number;
  }>();

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  threats.forEach(threat => {
    // Validate required fields
    if (!threat.source) {
      console.warn('[analytics-utils] Skipping threat with missing source:', threat);
      return;
    }

    const source = threat.source;

    if (!sourceStatsMap.has(source)) {
      sourceStatsMap.set(source, {
        total: 0,
        highConfidence: 0,
        totalConfidence: 0,
        iocTypes: new Set(),
        recentActivity: 0
      });
    }

    const stats = sourceStatsMap.get(source)!;
    stats.total++;
    stats.totalConfidence += (threat.confidence || 0);

    if ((threat.confidence || 0) >= 80) {
      stats.highConfidence++;
    }

    if (threat.ioc_type) {
      stats.iocTypes.add(threat.ioc_type);
    }

    if (threat.created_at) {
      const threatDate = new Date(threat.created_at);
      if (!isNaN(threatDate.getTime()) && threatDate > sevenDaysAgo) {
        stats.recentActivity++;
      }
    }
  });

  // Convert to array with calculated averages
  const result: SourceStats[] = [];

  sourceStatsMap.forEach((stats, source) => {
    result.push({
      source,
      total: stats.total,
      highConfidence: stats.highConfidence,
      avgConfidence: Math.round(stats.totalConfidence / stats.total),
      iocTypes: Array.from(stats.iocTypes),
      recentActivity: stats.recentActivity
    });
  });

  // Sort by total descending
  return result.sort((a, b) => b.total - a.total);
}

/**
 * Get collection metrics from localStorage
 */
export function getCollectionMetrics(): CollectionMetric[] {
  try {
    const stored = localStorage.getItem('collection-metrics');
    if (!stored) return [];

    const metrics: CollectionMetric[] = JSON.parse(stored);

    // Return last 10 collections, newest first
    return metrics.slice(-10).reverse();
  } catch (error) {
    console.error('Failed to load collection metrics:', error);
    return [];
  }
}

/**
 * Store collection metric in localStorage
 */
export function addCollectionMetric(metric: CollectionMetric): void {
  try {
    const stored = localStorage.getItem('collection-metrics');
    const metrics: CollectionMetric[] = stored ? JSON.parse(stored) : [];

    metrics.push(metric);

    // Keep only last 50 metrics
    const trimmed = metrics.slice(-50);

    localStorage.setItem('collection-metrics', JSON.stringify(trimmed));
  } catch (error) {
    console.error('Failed to store collection metric:', error);
  }
}

/**
 * Calculate collection statistics
 */
export function calculateCollectionStats(metrics: CollectionMetric[]): {
  avgDuration: number;
  successRate: number;
  lastCollection: string | null;
} {
  if (metrics.length === 0) {
    return {
      avgDuration: 0,
      successRate: 0,
      lastCollection: null
    };
  }

  const durations = metrics
    .filter(m => m.duration !== undefined)
    .map(m => m.duration!);

  const avgDuration = durations.length > 0
    ? durations.reduce((sum, d) => sum + d, 0) / durations.length
    : 0;

  const successCount = metrics.filter(m => m.status === 'success').length;
  const successRate = (successCount / metrics.length) * 100;

  const lastCollection = metrics.length > 0 ? metrics[0].timestamp : null;

  return {
    avgDuration,
    successRate,
    lastCollection
  };
}
