"""
Privacy Defense Mechanisms
- Content Security Policy (CSP) headers
- Privacy proxy filter for data sanitization
"""

from flask import request, Response
import re
import json

class PrivacyDefenses:
    """Privacy defense mechanisms for healthcare portal"""
    
    # Sensitive terms to sanitize
    SENSITIVE_TERMS = [
        'oncology', 'cancer', 'chemotherapy', 'tumor', 'malignant',
        'hiv', 'aids', 'antiretroviral',
        'mental health', 'depression', 'anxiety', 'psychiatric', 'therapy', 'counseling',
        'abortion', 'termination',
        'addiction', 'substance abuse', 'rehab',
        'std', 'sexually transmitted', 'herpes', 'syphilis',
        'erectile dysfunction', 'viagra',
        'fertility', 'ivf', 'infertility'
    ]
    
    @staticmethod
    def add_csp_headers(response):
        """
        Add Content Security Policy headers to restrict tracking
        """
        # Strict CSP that blocks external tracking scripts
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "  # Blocks connections to external tracking servers
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        )
        
        response.headers['Content-Security-Policy'] = csp_policy
        
        # Additional privacy headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        return response
    
    @staticmethod
    def sanitize_url(url):
        """
        Sanitize URL by removing or masking sensitive query parameters
        """
        if not url or '?' not in url:
            return url
        
        base_url, query_string = url.split('?', 1)
        
        # Check if query contains sensitive terms
        query_lower = query_string.lower()
        has_sensitive = any(term in query_lower for term in PrivacyDefenses.SENSITIVE_TERMS)
        
        if has_sensitive:
            # Replace sensitive query with generic placeholder
            return f"{base_url}?q=[REDACTED]"
        
        return url
    
    @staticmethod
    def sanitize_page_title(title):
        """
        Sanitize page title by masking sensitive terms
        """
        if not title:
            return title
        
        title_lower = title.lower()
        
        for term in PrivacyDefenses.SENSITIVE_TERMS:
            if term in title_lower:
                # Replace with generic term
                pattern = re.compile(re.escape(term), re.IGNORECASE)
                title = pattern.sub('[HEALTH TOPIC]', title)
        
        return title
    
    @staticmethod
    def sanitize_search_query(query):
        """
        Sanitize search query by masking sensitive terms
        """
        if not query:
            return query
        
        query_lower = query.lower()
        
        for term in PrivacyDefenses.SENSITIVE_TERMS:
            if term in query_lower:
                return '[REDACTED]'
        
        return query
    
    @staticmethod
    def sanitize_tracking_event(event_data):
        """
        Sanitize tracking event data before transmission
        """
        sanitized = event_data.copy()
        
        # Sanitize URL
        if 'page_url' in sanitized:
            sanitized['page_url'] = PrivacyDefenses.sanitize_url(sanitized['page_url'])
        
        # Sanitize page title
        if 'page_title' in sanitized:
            sanitized['page_title'] = PrivacyDefenses.sanitize_page_title(sanitized['page_title'])
        
        # Sanitize search query
        if 'query' in sanitized:
            sanitized['query'] = PrivacyDefenses.sanitize_search_query(sanitized['query'])
        
        # Sanitize form fields
        if 'form_fields' in sanitized:
            for key in sanitized['form_fields']:
                if any(term in key.lower() for term in ['search', 'query', 'q']):
                    sanitized['form_fields'][key] = PrivacyDefenses.sanitize_search_query(
                        sanitized['form_fields'][key]
                    )
        
        # Remove potentially identifying information
        if 'user_agent' in sanitized:
            # Generalize user agent
            sanitized['user_agent'] = 'Mozilla/5.0 (Generic Browser)'
        
        return sanitized


class PrivacyProxyFilter:
    """
    Privacy proxy that filters outgoing tracking requests
    """
    
    def __init__(self):
        self.blocked_requests = 0
        self.sanitized_requests = 0
        self.allowed_requests = 0
    
    def should_block_request(self, url, data):
        """
        Determine if tracking request should be blocked
        """
        # Block requests to known tracking domains
        tracking_domains = [
            'google-analytics.com',
            'facebook.com/tr',
            'doubleclick.net',
            'analytics.google.com'
        ]
        
        for domain in tracking_domains:
            if domain in url:
                return True
        
        return False
    
    def filter_outgoing_request(self, url, data):
        """
        Filter and sanitize outgoing tracking request
        """
        # Check if should block
        if self.should_block_request(url, data):
            self.blocked_requests += 1
            return None
        
        # Sanitize data
        if isinstance(data, dict):
            sanitized_data = PrivacyDefenses.sanitize_tracking_event(data)
            
            # Check if sanitization changed anything
            if sanitized_data != data:
                self.sanitized_requests += 1
            else:
                self.allowed_requests += 1
            
            return sanitized_data
        
        self.allowed_requests += 1
        return data
    
    def get_statistics(self):
        """Get proxy filter statistics"""
        total = self.blocked_requests + self.sanitized_requests + self.allowed_requests
        
        return {
            'total_requests': total,
            'blocked': self.blocked_requests,
            'sanitized': self.sanitized_requests,
            'allowed': self.allowed_requests,
            'block_rate': f"{(self.blocked_requests/total*100):.1f}%" if total > 0 else "0%",
            'sanitization_rate': f"{(self.sanitized_requests/total*100):.1f}%" if total > 0 else "0%"
        }


def apply_privacy_defenses_to_app(app):
    """
    Apply privacy defenses to Flask app
    """
    
    @app.after_request
    def add_security_headers(response):
        """Add CSP and security headers to all responses"""
        return PrivacyDefenses.add_csp_headers(response)
    
    return app


# Example usage for testing
if __name__ == '__main__':
    # Test sanitization
    print("Testing Privacy Defense Mechanisms")
    print("=" * 60)
    
    # Test URL sanitization
    test_urls = [
        "http://example.com/search?q=oncology",
        "http://example.com/search?q=diabetes",
        "http://example.com/topic/hiv",
        "http://example.com/dashboard"
    ]
    
    print("\nURL Sanitization:")
    for url in test_urls:
        sanitized = PrivacyDefenses.sanitize_url(url)
        print(f"  {url}")
        print(f"  → {sanitized}")
        print()
    
    # Test title sanitization
    test_titles = [
        "Search: oncology treatment",
        "Topic: HIV Services",
        "Mental Health Counseling",
        "Diabetes Management"
    ]
    
    print("\nTitle Sanitization:")
    for title in test_titles:
        sanitized = PrivacyDefenses.sanitize_page_title(title)
        print(f"  {title}")
        print(f"  → {sanitized}")
        print()
    
    # Test event sanitization
    test_event = {
        'page_url': 'http://example.com/search?q=cancer+treatment',
        'page_title': 'Search: cancer treatment',
        'query': 'cancer treatment',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print("\nEvent Sanitization:")
    print("Original:", json.dumps(test_event, indent=2))
    sanitized_event = PrivacyDefenses.sanitize_tracking_event(test_event)
    print("Sanitized:", json.dumps(sanitized_event, indent=2))
    
    # Test proxy filter
    print("\n" + "=" * 60)
    print("Privacy Proxy Filter Test:")
    proxy = PrivacyProxyFilter()
    
    test_requests = [
        ('http://localhost:3000/track', {'page_title': 'Oncology Services'}),
        ('http://google-analytics.com/collect', {'page': 'home'}),
        ('http://localhost:3000/track', {'page_title': 'Dashboard'}),
    ]
    
    for url, data in test_requests:
        result = proxy.filter_outgoing_request(url, data)
        if result is None:
            print(f"  BLOCKED: {url}")
        else:
            print(f"  ALLOWED: {url}")
    
    print("\nProxy Statistics:")
    stats = proxy.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

