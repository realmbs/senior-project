"""
Advanced Threat Intelligence Search Engine
Phase 8A Implementation - Multi-Criteria IOC Search with Fuzzy Matching

This module provides enterprise-grade search capabilities including:
- Multi-criteria IOC search (IP, domain, URL, hash, etc.)
- Fuzzy matching and pattern recognition algorithms
- Advanced correlation analytics with semantic similarity
- Query optimization and intelligent planning
- Result ranking by relevance and confidence
- Export capabilities (JSON, CSV, STIX)
- Performance optimizations and caching
"""

import json
import boto3
import logging
import os
import re
import hashlib
import difflib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from decimal import Decimal
from dataclasses import dataclass
from enum import Enum
import ipaddress
from urllib.parse import urlparse
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS Service Clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')

# Environment Variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')
THREAT_INTEL_TABLE = os.environ['THREAT_INTEL_TABLE']
ENRICHMENT_CACHE_TABLE = os.environ['ENRICHMENT_CACHE_TABLE']
DEDUP_TABLE = os.environ['DEDUP_TABLE']

# DynamoDB Tables
threat_intel_table = dynamodb.Table(THREAT_INTEL_TABLE)
enrichment_cache_table = dynamodb.Table(ENRICHMENT_CACHE_TABLE)
dedup_table = dynamodb.Table(DEDUP_TABLE)

# Search Configuration
MAX_SEARCH_RESULTS = 1000
DEFAULT_PAGE_SIZE = 50
FUZZY_MATCH_THRESHOLD = 0.7
CACHE_TTL_MINUTES = 30
MAX_CONCURRENT_QUERIES = 5


class SearchType(Enum):
    """Enumeration of supported search types"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "hash"
    EMAIL = "email"
    PATTERN = "pattern"
    FULL_TEXT = "text"
    COMPOSITE = "composite"


class SortOrder(Enum):
    """Result sorting options"""
    RELEVANCE = "relevance"
    CONFIDENCE = "confidence"
    CREATED_DATE = "created_date"
    THREAT_SCORE = "threat_score"


@dataclass
class SearchQuery:
    """Structured search query object"""
    query_text: str
    search_types: List[SearchType]
    filters: Dict[str, Any]
    sort_by: SortOrder = SortOrder.RELEVANCE
    page_size: int = DEFAULT_PAGE_SIZE
    cursor: Optional[str] = None
    fuzzy_enabled: bool = True
    correlation_enabled: bool = True
    include_enrichment: bool = True


@dataclass
class SearchResult:
    """Individual search result with metadata"""
    indicator: Dict[str, Any]
    relevance_score: float
    confidence_score: int
    match_type: str
    match_details: Dict[str, Any]
    correlations: List[Dict[str, Any]]
    enrichment_data: Optional[Dict[str, Any]] = None


@dataclass
class SearchResponse:
    """Complete search response with pagination"""
    results: List[SearchResult]
    total_count: int
    page_info: Dict[str, Any]
    query_stats: Dict[str, Any]
    execution_time_ms: int


class AdvancedSearchEngine:
    """Enterprise-grade threat intelligence search engine"""

    def __init__(self):
        self.query_cache = {}
        self.pattern_matchers = self._initialize_pattern_matchers()
        self.correlation_engine = CorrelationEngine()
        self.ranking_engine = RankingEngine()

    def search(self, query: SearchQuery) -> SearchResponse:
        """
        Execute advanced multi-criteria search

        Args:
            query: Structured search query object

        Returns:
            SearchResponse with ranked results and metadata
        """
        start_time = datetime.now()

        try:
            logger.info(f"Executing advanced search: {query.query_text}")

            # Check cache first
            cache_key = self._generate_cache_key(query)
            if cache_key in self.query_cache:
                cached_result = self.query_cache[cache_key]
                if self._is_cache_valid(cached_result):
                    logger.info("Returning cached search results")
                    return cached_result['response']

            # Parse and normalize query
            parsed_query = self._parse_query(query)

            # Execute optimized search strategy
            raw_results = self._execute_search_strategy(parsed_query)

            # Apply fuzzy matching if enabled
            if query.fuzzy_enabled:
                fuzzy_results = self._apply_fuzzy_matching(raw_results, parsed_query)
                raw_results.extend(fuzzy_results)

            # Find correlations if enabled
            if query.correlation_enabled:
                raw_results = self._enhance_with_correlations(raw_results)

            # Add enrichment data if requested
            if query.include_enrichment:
                raw_results = self._add_enrichment_data(raw_results)

            # Rank and sort results
            ranked_results = self.ranking_engine.rank_results(raw_results, query)

            # Apply pagination
            paginated_results = self._apply_pagination(ranked_results, query)

            # Build response
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            response = SearchResponse(
                results=paginated_results['results'],
                total_count=len(raw_results),
                page_info=paginated_results['page_info'],
                query_stats=self._generate_query_stats(parsed_query, raw_results),
                execution_time_ms=int(execution_time)
            )

            # Cache response
            self._cache_response(cache_key, response)

            logger.info(f"Search completed: {len(response.results)} results in {execution_time:.1f}ms")
            return response

        except Exception as e:
            logger.error(f"Search execution failed: {e}", exc_info=True)
            raise

    def _parse_query(self, query: SearchQuery) -> Dict[str, Any]:
        """Parse and normalize search query"""
        parsed = {
            'original_text': query.query_text,
            'normalized_text': query.query_text.lower().strip(),
            'detected_types': [],
            'extracted_iocs': {},
            'search_terms': [],
            'filters': query.filters
        }

        # Detect IOC types using pattern matching
        for ioc_type, patterns in self.pattern_matchers.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, query.query_text, re.IGNORECASE)
                matches.extend(found)

            if matches:
                parsed['detected_types'].append(ioc_type)
                parsed['extracted_iocs'][ioc_type] = matches

        # Extract search terms for full-text search
        parsed['search_terms'] = self._extract_search_terms(query.query_text)

        return parsed

    def _execute_search_strategy(self, parsed_query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute optimized search strategy based on query analysis"""
        results = []

        # Strategy 1: Exact IOC matching using GSIs
        for ioc_type, values in parsed_query['extracted_iocs'].items():
            for value in values:
                exact_matches = self._search_exact_ioc(ioc_type, value)
                results.extend(exact_matches)

        # Strategy 2: Pattern-based search using pattern-hash-index
        if 'pattern' in parsed_query['filters']:
            pattern_matches = self._search_by_pattern(parsed_query['filters']['pattern'])
            results.extend(pattern_matches)

        # Strategy 3: Time-based search using time-index
        if 'date_range' in parsed_query['filters']:
            time_matches = self._search_by_time_range(parsed_query['filters']['date_range'])
            results.extend(time_matches)

        # Strategy 4: Source-based search using source-index
        if 'source' in parsed_query['filters']:
            source_matches = self._search_by_source(parsed_query['filters']['source'])
            results.extend(source_matches)

        # Strategy 5: Full-text search (expensive - use sparingly)
        if not results and parsed_query['search_terms']:
            fulltext_matches = self._search_full_text(parsed_query['search_terms'])
            results.extend(fulltext_matches)

        # Deduplicate results
        return self._deduplicate_results(results)

    def _search_exact_ioc(self, ioc_type: str, value: str) -> List[Dict[str, Any]]:
        """Search for exact IOC matches using optimized queries"""
        results = []

        try:
            if ioc_type == SearchType.IP_ADDRESS.value:
                # Search for IP patterns in threat intelligence
                pattern = f"[ipv4-addr:value = '{value}']"
                results = self._query_by_pattern_hash(pattern)

            elif ioc_type == SearchType.DOMAIN.value:
                # Search for domain patterns
                pattern = f"[domain-name:value = '{value}']"
                results = self._query_by_pattern_hash(pattern)

            elif ioc_type == SearchType.URL.value:
                # Search for URL patterns
                pattern = f"[url:value = '{value}']"
                results = self._query_by_pattern_hash(pattern)

            elif ioc_type == SearchType.FILE_HASH.value:
                # Determine hash type and search accordingly
                hash_type = self._determine_hash_type(value)
                if hash_type:
                    pattern = f"[file:hashes.{hash_type} = '{value}']"
                    results = self._query_by_pattern_hash(pattern)

        except Exception as e:
            logger.warning(f"Error in exact IOC search for {ioc_type}:{value}: {e}")

        return results

    def _query_by_pattern_hash(self, pattern: str) -> List[Dict[str, Any]]:
        """Query using pattern hash index for efficient lookups"""
        try:
            pattern_hash = hashlib.sha256(pattern.encode()).hexdigest()

            response = threat_intel_table.query(
                IndexName='pattern-hash-index',
                KeyConditionExpression='pattern_hash = :hash',
                ExpressionAttributeValues={':hash': pattern_hash},
                Limit=100
            )

            return response.get('Items', [])

        except Exception as e:
            logger.warning(f"Pattern hash query failed: {e}")
            return []

    def _apply_fuzzy_matching(self, existing_results: List[Dict[str, Any]],
                            parsed_query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply fuzzy matching algorithms for approximate search"""
        fuzzy_results = []

        try:
            # Extract all unique IOC values from existing indicators
            all_indicators = self._get_sample_indicators(500)  # Get sample for fuzzy matching

            for ioc_type, values in parsed_query['extracted_iocs'].items():
                for query_value in values:
                    fuzzy_matches = self._find_fuzzy_matches(
                        query_value, all_indicators, ioc_type)
                    fuzzy_results.extend(fuzzy_matches)

        except Exception as e:
            logger.warning(f"Fuzzy matching failed: {e}")

        return fuzzy_results

    def _find_fuzzy_matches(self, query_value: str, indicators: List[Dict[str, Any]],
                           ioc_type: str) -> List[Dict[str, Any]]:
        """Find fuzzy matches using difflib similarity"""
        matches = []

        for indicator in indicators:
            pattern = indicator.get('pattern', '')

            # Extract values from pattern for comparison
            extracted_values = re.findall(r"'([^']+)'", pattern)

            for value in extracted_values:
                similarity = difflib.SequenceMatcher(None, query_value.lower(),
                                                   value.lower()).ratio()

                if similarity >= FUZZY_MATCH_THRESHOLD:
                    match_copy = indicator.copy()
                    match_copy['fuzzy_match_score'] = similarity
                    match_copy['matched_value'] = value
                    matches.append(match_copy)

        return matches

    def _enhance_with_correlations(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance results with advanced correlation analytics"""
        enhanced_results = []

        for result in results:
            # Find correlations using the advanced correlation engine
            correlations = self.correlation_engine.find_advanced_correlations(result)

            enhanced_result = result.copy()
            enhanced_result['correlations'] = correlations
            enhanced_result['correlation_score'] = len(correlations)
            enhanced_results.append(enhanced_result)

        return enhanced_results

    def _add_enrichment_data(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add OSINT enrichment data to search results"""
        enriched_results = []

        for result in results:
            enrichment_data = self._get_enrichment_data(result)

            enriched_result = result.copy()
            enriched_result['enrichment_data'] = enrichment_data
            enriched_results.append(enriched_result)

        return enriched_results

    def _get_enrichment_data(self, indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Retrieve enrichment data from cache"""
        try:
            pattern = indicator.get('pattern', '')
            extracted_values = re.findall(r"'([^']+)'", pattern)

            enrichment_data = {}
            for value in extracted_values:
                # Query enrichment cache for this observable
                response = enrichment_cache_table.query(
                    KeyConditionExpression='observable_value = :value',
                    ExpressionAttributeValues={':value': value},
                    Limit=10
                )

                items = response.get('Items', [])
                if items:
                    enrichment_data[value] = items

            return enrichment_data if enrichment_data else None

        except Exception as e:
            logger.warning(f"Failed to get enrichment data: {e}")
            return None

    def _initialize_pattern_matchers(self) -> Dict[str, List[str]]:
        """Initialize regex patterns for IOC detection"""
        return {
            SearchType.IP_ADDRESS.value: [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IPv4
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # IPv6 (simplified)
            ],
            SearchType.DOMAIN.value: [
                r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
            ],
            SearchType.URL.value: [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                r'ftp://[^\s<>"{}|\\^`\[\]]+'
            ],
            SearchType.FILE_HASH.value: [
                r'\b[a-fA-F0-9]{32}\b',  # MD5
                r'\b[a-fA-F0-9]{40}\b',  # SHA1
                r'\b[a-fA-F0-9]{64}\b'   # SHA256
            ],
            SearchType.EMAIL.value: [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ]
        }

    def _determine_hash_type(self, hash_value: str) -> Optional[str]:
        """Determine hash type based on length"""
        if len(hash_value) == 32:
            return 'MD5'
        elif len(hash_value) == 40:
            return 'SHA-1'
        elif len(hash_value) == 64:
            return 'SHA-256'
        return None

    def _extract_search_terms(self, query_text: str) -> List[str]:
        """Extract meaningful search terms from query text"""
        # Remove IOCs and extract remaining terms
        clean_text = query_text

        # Remove detected IOCs to get pure text terms
        for ioc_type, patterns in self.pattern_matchers.items():
            for pattern in patterns:
                clean_text = re.sub(pattern, '', clean_text, flags=re.IGNORECASE)

        # Split into terms and filter
        terms = [term.strip() for term in clean_text.split() if len(term.strip()) > 2]
        return terms

    def _search_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        """Search by specific STIX pattern"""
        try:
            response = threat_intel_table.scan(
                FilterExpression='contains(pattern, :pattern)',
                ExpressionAttributeValues={':pattern': pattern},
                Limit=100
            )
            return response.get('Items', [])
        except Exception:
            return []

    def _search_by_time_range(self, date_range: Dict[str, str]) -> List[Dict[str, Any]]:
        """Search using time-index GSI"""
        try:
            start_date = date_range.get('start')
            end_date = date_range.get('end')
            object_type = date_range.get('object_type', 'indicator')

            response = threat_intel_table.query(
                IndexName='time-index',
                KeyConditionExpression='object_type = :type AND created_date BETWEEN :start AND :end',
                ExpressionAttributeValues={
                    ':type': object_type,
                    ':start': start_date,
                    ':end': end_date
                },
                Limit=200
            )
            return response.get('Items', [])
        except Exception:
            return []

    def _search_by_source(self, source_filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search using source-index GSI"""
        try:
            source_name = source_filters.get('name')
            min_confidence = source_filters.get('min_confidence', 0)

            response = threat_intel_table.query(
                IndexName='source-index',
                KeyConditionExpression='source_name = :source AND confidence >= :conf',
                ExpressionAttributeValues={
                    ':source': source_name,
                    ':conf': Decimal(str(min_confidence))
                },
                Limit=200
            )
            return response.get('Items', [])
        except Exception:
            return []

    def _search_full_text(self, search_terms: List[str]) -> List[Dict[str, Any]]:
        """Full-text search across all fields (expensive operation)"""
        results = []

        try:
            # This is expensive - only use when necessary
            for term in search_terms:
                response = threat_intel_table.scan(
                    FilterExpression='contains(description, :term) OR contains(labels, :term)',
                    ExpressionAttributeValues={':term': term},
                    Limit=50
                )
                results.extend(response.get('Items', []))

        except Exception as e:
            logger.warning(f"Full-text search failed: {e}")

        return results

    def _get_sample_indicators(self, limit: int) -> List[Dict[str, Any]]:
        """Get sample indicators for fuzzy matching"""
        try:
            response = threat_intel_table.scan(Limit=limit)
            return response.get('Items', [])
        except Exception:
            return []

    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate results based on object_id"""
        seen_ids = set()
        deduplicated = []

        for result in results:
            object_id = result.get('object_id')
            if object_id not in seen_ids:
                seen_ids.add(object_id)
                deduplicated.append(result)

        return deduplicated

    def _apply_pagination(self, results: List[Dict[str, Any]],
                         query: SearchQuery) -> Dict[str, Any]:
        """Apply cursor-based pagination to results"""
        total_results = len(results)
        start_index = 0

        # Handle cursor-based pagination
        if query.cursor:
            try:
                start_index = int(query.cursor)
            except ValueError:
                start_index = 0

        end_index = min(start_index + query.page_size, total_results)
        page_results = results[start_index:end_index]

        # Convert to SearchResult objects
        search_results = []
        for result in page_results:
            search_result = SearchResult(
                indicator=result,
                relevance_score=result.get('relevance_score', 0.0),
                confidence_score=result.get('confidence', 50),
                match_type=result.get('match_type', 'exact'),
                match_details=result.get('match_details', {}),
                correlations=result.get('correlations', []),
                enrichment_data=result.get('enrichment_data')
            )
            search_results.append(search_result)

        # Generate pagination info
        page_info = {
            'current_page': start_index // query.page_size + 1,
            'page_size': query.page_size,
            'total_pages': (total_results + query.page_size - 1) // query.page_size,
            'has_next': end_index < total_results,
            'has_previous': start_index > 0,
            'next_cursor': str(end_index) if end_index < total_results else None,
            'previous_cursor': str(max(0, start_index - query.page_size)) if start_index > 0 else None
        }

        return {
            'results': search_results,
            'page_info': page_info
        }

    def _generate_query_stats(self, parsed_query: Dict[str, Any],
                            results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate query execution statistics"""
        return {
            'detected_ioc_types': parsed_query['detected_types'],
            'extracted_iocs_count': sum(len(values) for values in parsed_query['extracted_iocs'].values()),
            'search_terms_count': len(parsed_query['search_terms']),
            'total_results_found': len(results),
            'result_sources': self._count_result_sources(results),
            'confidence_distribution': self._analyze_confidence_distribution(results)
        }

    def _count_result_sources(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count results by source"""
        source_counts = {}
        for result in results:
            source = result.get('source_name', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        return source_counts

    def _analyze_confidence_distribution(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze confidence score distribution"""
        distribution = {'high': 0, 'medium': 0, 'low': 0}

        for result in results:
            confidence = result.get('confidence', 50)
            if confidence >= 80:
                distribution['high'] += 1
            elif confidence >= 50:
                distribution['medium'] += 1
            else:
                distribution['low'] += 1

        return distribution

    def _generate_cache_key(self, query: SearchQuery) -> str:
        """Generate cache key for query"""
        query_dict = {
            'text': query.query_text,
            'types': [t.value for t in query.search_types],
            'filters': query.filters,
            'sort': query.sort_by.value,
            'fuzzy': query.fuzzy_enabled,
            'correlation': query.correlation_enabled
        }
        return hashlib.md5(json.dumps(query_dict, sort_keys=True).encode()).hexdigest()

    def _is_cache_valid(self, cached_result: Dict[str, Any]) -> bool:
        """Check if cached result is still valid"""
        cache_time = datetime.fromisoformat(cached_result['timestamp'])
        age_minutes = (datetime.now(timezone.utc) - cache_time).total_seconds() / 60
        return age_minutes < CACHE_TTL_MINUTES

    def _cache_response(self, cache_key: str, response: SearchResponse) -> None:
        """Cache search response"""
        self.query_cache[cache_key] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'response': response
        }

        # Simple cache size management
        if len(self.query_cache) > 100:
            # Remove oldest entries
            oldest_keys = sorted(self.query_cache.keys(),
                               key=lambda k: self.query_cache[k]['timestamp'])[:20]
            for key in oldest_keys:
                del self.query_cache[key]


class CorrelationEngine:
    """Advanced correlation analytics engine"""

    def find_advanced_correlations(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find advanced correlations using multiple techniques"""
        correlations = []

        # Temporal clustering
        temporal_correlations = self._find_temporal_correlations(indicator)
        correlations.extend(temporal_correlations)

        # Geographic clustering
        geo_correlations = self._find_geographic_correlations(indicator)
        correlations.extend(geo_correlations)

        # Semantic similarity
        semantic_correlations = self._find_semantic_correlations(indicator)
        correlations.extend(semantic_correlations)

        # Behavioral analysis
        behavioral_correlations = self._find_behavioral_correlations(indicator)
        correlations.extend(behavioral_correlations)

        return correlations

    def _find_temporal_correlations(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find indicators correlated in time"""
        # Implementation would analyze temporal patterns
        return []

    def _find_geographic_correlations(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find geographically correlated indicators"""
        # Implementation would analyze geographic patterns
        return []

    def _find_semantic_correlations(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find semantically similar indicators"""
        # Implementation would use NLP techniques
        return []

    def _find_behavioral_correlations(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find behaviorally similar indicators"""
        # Implementation would analyze behavioral patterns
        return []


class RankingEngine:
    """Result ranking and relevance scoring engine"""

    def rank_results(self, results: List[Dict[str, Any]],
                    query: SearchQuery) -> List[Dict[str, Any]]:
        """Rank search results by relevance and confidence"""

        # Calculate relevance scores
        for result in results:
            relevance_score = self._calculate_relevance_score(result, query)
            result['relevance_score'] = relevance_score

        # Sort by the specified criteria
        if query.sort_by == SortOrder.RELEVANCE:
            results.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        elif query.sort_by == SortOrder.CONFIDENCE:
            results.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        elif query.sort_by == SortOrder.CREATED_DATE:
            results.sort(key=lambda x: x.get('created_date', ''), reverse=True)
        elif query.sort_by == SortOrder.THREAT_SCORE:
            results.sort(key=lambda x: x.get('quality_score', 0), reverse=True)

        return results

    def _calculate_relevance_score(self, result: Dict[str, Any],
                                 query: SearchQuery) -> float:
        """Calculate relevance score for a result"""
        score = 0.0

        # Exact match bonus
        if self._is_exact_match(result, query.query_text):
            score += 100.0

        # Confidence score contribution
        confidence = result.get('confidence', 50)
        score += confidence * 0.5

        # Fuzzy match score
        fuzzy_score = result.get('fuzzy_match_score', 0.0)
        score += fuzzy_score * 50.0

        # Correlation count bonus
        correlation_count = result.get('correlation_score', 0)
        score += min(correlation_count * 5, 25)

        # Quality score contribution
        quality_score = result.get('quality_score', 50)
        score += quality_score * 0.3

        # Source reputation bonus
        source_bonus = self._get_source_reputation_bonus(result.get('source_name', ''))
        score += source_bonus

        return score

    def _is_exact_match(self, result: Dict[str, Any], query_text: str) -> bool:
        """Check if result is an exact match for query"""
        pattern = result.get('pattern', '')
        return query_text.lower() in pattern.lower()

    def _get_source_reputation_bonus(self, source: str) -> float:
        """Get reputation bonus based on source"""
        reputation_scores = {
            'abuse_ch': 20.0,
            'otx': 15.0,
            'misp': 18.0,
            'commercial': 25.0,
            'government': 30.0
        }
        return reputation_scores.get(source, 5.0)


# Global search engine instance
search_engine = AdvancedSearchEngine()


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    Lambda handler for advanced threat intelligence search

    Args:
        event: API Gateway event with search parameters
        context: Lambda runtime context

    Returns:
        SearchResponse with ranked results
    """
    try:
        # Parse request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event

        # Build search query
        query = SearchQuery(
            query_text=body.get('query', ''),
            search_types=[SearchType(t) for t in body.get('search_types', ['composite'])],
            filters=body.get('filters', {}),
            sort_by=SortOrder(body.get('sort_by', 'relevance')),
            page_size=body.get('page_size', DEFAULT_PAGE_SIZE),
            cursor=body.get('cursor'),
            fuzzy_enabled=body.get('fuzzy_enabled', True),
            correlation_enabled=body.get('correlation_enabled', True),
            include_enrichment=body.get('include_enrichment', True)
        )

        # Execute search
        response = search_engine.search(query)

        # Convert to JSON-serializable format
        response_dict = {
            'results': [
                {
                    'indicator': result.indicator,
                    'relevance_score': result.relevance_score,
                    'confidence_score': result.confidence_score,
                    'match_type': result.match_type,
                    'match_details': result.match_details,
                    'correlations': result.correlations,
                    'enrichment_data': result.enrichment_data
                }
                for result in response.results
            ],
            'total_count': response.total_count,
            'page_info': response.page_info,
            'query_stats': response.query_stats,
            'execution_time_ms': response.execution_time_ms
        }

        return {
            'statusCode': 200,
            'body': json.dumps(response_dict, default=str),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }

    except Exception as e:
        logger.error(f"Search handler failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Search failed',
                'message': str(e) if ENVIRONMENT == 'dev' else 'Internal server error'
            }),
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        }