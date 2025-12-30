"""
VirusTotal Threat Intelligence Integration
Phase 3: Real threat intel API integration
"""

import requests
import json
from typing import Optional, Dict, List
from datetime import datetime
import os
from functools import lru_cache

VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
VT_TIMEOUT = 10

class ThreatIntelError(Exception):
    """Raised when threat intel lookup fails"""
    pass

class VirusTotalClient:
    """VirusTotal API client for hash and IP lookups"""
    
    def __init__(self, api_key: str = VT_API_KEY):
        self.api_key = api_key
        self.headers = {'x-apikey': api_key} if api_key else {}
        self.enabled = bool(api_key)
    
    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash (MD5, SHA-1, SHA-256)
        
        Returns:
            {
                'hash': str,
                'verdict': 'malicious' | 'suspicious' | 'undetected' | 'harmless',
                'detections': int,
                'vendors': int,
                'last_analysis': str (ISO datetime),
                'tags': [str],
                'community_score': float
            }
        """
        if not self.enabled:
            return self._mock_hash_response(file_hash)
        
        try:
            url = f'{VT_BASE_URL}/files/{file_hash}'
            response = requests.get(url, headers=self.headers, timeout=VT_TIMEOUT)
            
            if response.status_code == 404:
                return None  # Hash not found
            
            response.raise_for_status()
            data = response.json()['data']
            
            attrs = data.get('attributes', {})
            analysis = attrs.get('last_analysis_stats', {})
            
            # Determine verdict
            detections = analysis.get('malicious', 0)
            vendors = (
                analysis.get('malicious', 0) +
                analysis.get('suspicious', 0) +
                analysis.get('undetected', 0) +
                analysis.get('harmless', 0)
            )
            
            if detections > 0:
                verdict = 'malicious' if detections >= 5 else 'suspicious'
            else:
                verdict = 'harmless'
            
            return {
                'hash': file_hash,
                'verdict': verdict,
                'detections': detections,
                'vendors': vendors,
                'last_analysis': attrs.get('last_analysis_date', ''),
                'tags': attrs.get('tags', []),
                'community_score': attrs.get('reputation', 0)
            }
        
        except requests.exceptions.RequestException as e:
            raise ThreatIntelError(f'VirusTotal hash lookup failed: {e}')
    
    def lookup_ip(self, ip_address: str) -> Optional[Dict]:
        """
        Look up an IP address reputation
        
        Returns:
            {
                'ip': str,
                'verdict': 'malicious' | 'suspicious' | 'harmless',
                'threat_types': [str],
                'detections': int,
                'vendors': int,
                'last_analysis': str (ISO datetime),
                'asn': str,
                'country': str,
                'community_score': int
            }
        """
        if not self.enabled:
            return self._mock_ip_response(ip_address)
        
        try:
            url = f'{VT_BASE_URL}/ip_addresses/{ip_address}'
            response = requests.get(url, headers=self.headers, timeout=VT_TIMEOUT)
            
            if response.status_code == 404:
                return None  # IP not found
            
            response.raise_for_status()
            data = response.json()['data']
            
            attrs = data.get('attributes', {})
            analysis = attrs.get('last_analysis_stats', {})
            
            # Determine verdict
            detections = analysis.get('malicious', 0)
            vendors = (
                analysis.get('malicious', 0) +
                analysis.get('suspicious', 0) +
                analysis.get('undetected', 0) +
                analysis.get('harmless', 0)
            )
            
            if detections > 0:
                verdict = 'malicious' if detections >= 5 else 'suspicious'
            else:
                verdict = 'harmless'
            
            # Get AS and country info
            as_info = attrs.get('asn', {})
            whois = attrs.get('last_whois_date', '')
            
            return {
                'ip': ip_address,
                'verdict': verdict,
                'threat_types': attrs.get('threat_types', []),
                'detections': detections,
                'vendors': vendors,
                'last_analysis': attrs.get('last_analysis_date', ''),
                'asn': as_info.get('asn', '') if isinstance(as_info, dict) else str(as_info),
                'country': attrs.get('country', ''),
                'community_score': attrs.get('reputation', 0)
            }
        
        except requests.exceptions.RequestException as e:
            raise ThreatIntelError(f'VirusTotal IP lookup failed: {e}')
    
    def lookup_domain(self, domain: str) -> Optional[Dict]:
        """
        Look up a domain reputation
        
        Returns:
            {
                'domain': str,
                'verdict': 'malicious' | 'suspicious' | 'harmless',
                'detections': int,
                'vendors': int,
                'categories': [str],
                'community_score': int
            }
        """
        if not self.enabled:
            return self._mock_domain_response(domain)
        
        try:
            url = f'{VT_BASE_URL}/domains/{domain}'
            response = requests.get(url, headers=self.headers, timeout=VT_TIMEOUT)
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            data = response.json()['data']
            
            attrs = data.get('attributes', {})
            analysis = attrs.get('last_analysis_stats', {})
            
            detections = analysis.get('malicious', 0)
            vendors = (
                analysis.get('malicious', 0) +
                analysis.get('suspicious', 0) +
                analysis.get('undetected', 0) +
                analysis.get('harmless', 0)
            )
            
            if detections > 0:
                verdict = 'malicious' if detections >= 5 else 'suspicious'
            else:
                verdict = 'harmless'
            
            return {
                'domain': domain,
                'verdict': verdict,
                'detections': detections,
                'vendors': vendors,
                'categories': attrs.get('categories', {}),
                'community_score': attrs.get('reputation', 0)
            }
        
        except requests.exceptions.RequestException as e:
            raise ThreatIntelError(f'VirusTotal domain lookup failed: {e}')
    
    # Mock responses for testing/demo without API key
    @staticmethod
    def _mock_hash_response(file_hash: str) -> Dict:
        """Generate mock response for hash lookup"""
        is_suspicious = file_hash.lower().endswith('bad')
        return {
            'hash': file_hash,
            'verdict': 'suspicious' if is_suspicious else 'harmless',
            'detections': 5 if is_suspicious else 0,
            'vendors': 72,
            'last_analysis': datetime.now().isoformat(),
            'tags': ['trojan', 'worm'] if is_suspicious else [],
            'community_score': -32 if is_suspicious else 0
        }
    
    @staticmethod
    def _mock_ip_response(ip_address: str) -> Dict:
        """Generate mock response for IP lookup"""
        is_suspicious = ip_address.startswith('192.0.2.')  # TEST-NET-1
        return {
            'ip': ip_address,
            'verdict': 'suspicious' if is_suspicious else 'harmless',
            'threat_types': ['botnet', 'ddos'] if is_suspicious else [],
            'detections': 12 if is_suspicious else 0,
            'vendors': 90,
            'last_analysis': datetime.now().isoformat(),
            'asn': 'AS15169' if not is_suspicious else 'AS64512',
            'country': 'US',
            'community_score': -42 if is_suspicious else 5
        }
    
    @staticmethod
    def _mock_domain_response(domain: str) -> Dict:
        """Generate mock response for domain lookup"""
        is_suspicious = 'malware' in domain.lower() or 'phish' in domain.lower()
        return {
            'domain': domain,
            'verdict': 'malicious' if is_suspicious else 'harmless',
            'detections': 15 if is_suspicious else 0,
            'vendors': 85,
            'categories': {'malware': 1, 'trojan': 1} if is_suspicious else {},
            'community_score': -58 if is_suspicious else 0
        }


class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation"""
    
    def __init__(self, api_key: str = ''):
        self.api_key = api_key or os.getenv('ABUSEIPDB_API_KEY', '')
        self.headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        } if self.api_key else {}
        self.enabled = bool(self.api_key)
        self.base_url = 'https://api.abuseipdb.com/api/v2'
    
    def check_ip(self, ip_address: str, days: int = 90) -> Optional[Dict]:
        """
        Check IP reputation on AbuseIPDB
        
        Returns:
            {
                'ip': str,
                'abuse_score': int (0-100),
                'reports': int,
                'categories': [str],
                'verdict': 'malicious' | 'suspicious' | 'harmless'
            }
        """
        if not self.enabled:
            return self._mock_check_response(ip_address)
        
        try:
            params = {'ipAddress': ip_address, 'maxAgeInDays': days}
            response = requests.get(
                f'{self.base_url}/check',
                headers=self.headers,
                params=params,
                timeout=VT_TIMEOUT
            )
            response.raise_for_status()
            
            data = response.json()['data']
            
            score = data.get('abuseConfidenceScore', 0)
            verdict = 'malicious' if score >= 75 else 'suspicious' if score >= 25 else 'harmless'
            
            return {
                'ip': ip_address,
                'abuse_score': score,
                'reports': data.get('totalReports', 0),
                'categories': data.get('usageType', []),
                'verdict': verdict
            }
        
        except requests.exceptions.RequestException as e:
            raise ThreatIntelError(f'AbuseIPDB check failed: {e}')
    
    @staticmethod
    def _mock_check_response(ip_address: str) -> Dict:
        """Generate mock response"""
        is_test = ip_address.startswith('192.0.2.')
        return {
            'ip': ip_address,
            'abuse_score': 85 if is_test else 0,
            'reports': 12 if is_test else 0,
            'categories': ['Scanner', 'Attacks'] if is_test else [],
            'verdict': 'malicious' if is_test else 'harmless'
        }


# Global clients
vt_client = VirusTotalClient()
abuseipdb_client = AbuseIPDBClient()


def lookup_ioc_threat_intel(ioc_value: str, ioc_type: str = 'hash') -> Optional[Dict]:
    """
    Multi-source threat intelligence lookup
    
    Args:
        ioc_value: Hash, IP, or domain
        ioc_type: 'hash', 'ip', or 'domain'
    
    Returns:
        Combined threat intelligence dict
    """
    try:
        if ioc_type == 'hash':
            vt_result = vt_client.lookup_hash(ioc_value)
            return {**vt_result, 'source': 'VirusTotal'} if vt_result else None
        
        elif ioc_type == 'ip':
            results = []
            
            vt_result = vt_client.lookup_ip(ioc_value)
            if vt_result:
                results.append({**vt_result, 'source': 'VirusTotal'})
            
            abuse_result = abuseipdb_client.check_ip(ioc_value)
            if abuse_result:
                results.append({**abuse_result, 'source': 'AbuseIPDB'})
            
            # Merge results, prefer malicious verdict
            if results:
                merged = {'ip': ioc_value, 'verdicts': []}
                for result in results:
                    merged['verdicts'].append({
                        'source': result.get('source'),
                        'verdict': result.get('verdict'),
                        'score': result.get('abuse_score') or result.get('community_score', 0)
                    })
                return merged
            return None
        
        elif ioc_type == 'domain':
            vt_result = vt_client.lookup_domain(ioc_value)
            return {**vt_result, 'source': 'VirusTotal'} if vt_result else None
        
        else:
            return None
    
    except ThreatIntelError as e:
        return {'error': str(e), 'ioc': ioc_value}
