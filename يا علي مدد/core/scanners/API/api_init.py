#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════╗
║              API Vulnerabilities Scanner Module              ║
║              Part of AlBaTTaR BUGS Framework                 ║
╚══════════════════════════════════════════════════════════════╝

This module contains specialized scanners for API vulnerabilities:
- API Abuse & Rate Limiting
- GraphQL Vulnerabilities
- REST API Security Issues
- API Key Exposure

Author: ROBIN | @ll bUg
Version: 1.0.0
"""

from .api_abuse import APIAbuseScanner
from .graphql_scanner import GraphQLScanner
from .rest_api_scanner import RESTAPIScanner
from .api_key_exposure import APIKeyExposureScanner

__all__ = [
    'APIAbuseScanner',
    'GraphQLScanner',
    'RESTAPIScanner',
    'APIKeyExposureScanner'
]

__version__ = '1.0.0'
__author__ = 'ROBIN | @ll bUg'

# Scanner metadata
SCANNERS = {
    'api_abuse': {
        'name': 'API Abuse Scanner',
        'description': 'Detects API abuse and rate limiting issues',
        'severity': 'high',
        'class': APIAbuseScanner
    },
    'graphql': {
        'name': 'GraphQL Scanner',
        'description': 'Scans for GraphQL vulnerabilities',
        'severity': 'high',
        'class': GraphQLScanner
    },
    'rest_api': {
        'name': 'REST API Scanner',
        'description': 'Detects REST API security issues',
        'severity': 'critical',
        'class': RESTAPIScanner
    },
    'api_key_exposure': {
        'name': 'API Key Exposure Scanner',
        'description': 'Finds exposed API keys and secrets',
        'severity': 'critical',
        'class': APIKeyExposureScanner
    }
}

def get_scanner(scanner_name):
    """Get scanner class by name"""
    if scanner_name in SCANNERS:
        return SCANNERS[scanner_name]['class']
    return None

def list_scanners():
    """List all available API scanners"""
    return list(SCANNERS.keys())
