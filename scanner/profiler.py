"""
Target Profiler

Fingerprints target servers to identify:
- Server software (nginx, Apache, IIS, etc.)
- Proxy/CDN presence (Cloudflare, Akamai, AWS)
- HTTP version support
- Connection behavior
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from core.connection import RawHTTPClient
from core.parser import HTTPResponseParser, HTTPResponse
from config import SERVER_SIGNATURES


class ServerType(Enum):
    """Known server types"""
    NGINX = "nginx"
    APACHE = "apache"
    IIS = "iis"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS = "aws"
    FASTLY = "fastly"
    VARNISH = "varnish"
    HAPROXY = "haproxy"
    GUNICORN = "gunicorn"
    UVICORN = "uvicorn"
    TOMCAT = "tomcat"
    NODEJS = "nodejs"
    UNKNOWN = "unknown"


@dataclass
class ServerProfile:
    """Profile of a target server"""
    # Basic info
    hostname: str
    port: int
    uses_ssl: bool
    
    # Server identification
    server_header: str = ""
    detected_servers: Set[ServerType] = field(default_factory=set)
    is_behind_proxy: bool = False
    is_behind_cdn: bool = False
    
    # HTTP capabilities
    supports_http11: bool = True
    supports_http2: bool = False
    supports_keep_alive: bool = True
    supports_chunked: bool = True
    
    # Connection behavior
    max_keep_alive_requests: int = 0
    connection_timeout: float = 0.0
    
    # Header handling
    allows_duplicate_headers: bool = False
    strips_invalid_headers: bool = False
    normalizes_header_case: bool = False
    
    # Smuggling-relevant hints
    hints: List[str] = field(default_factory=list)
    
    def add_hint(self, hint: str):
        """Add a profiling hint"""
        if hint not in self.hints:
            self.hints.append(hint)
            
    @property
    def risk_level(self) -> str:
        """Estimate smuggling risk based on profile"""
        # Multi-tier architecture increases risk
        if self.is_behind_proxy or self.is_behind_cdn:
            if len(self.detected_servers) > 1:
                return "HIGH"
            return "MEDIUM"
        return "LOW"


class TargetProfiler:
    """
    Profiles target servers to gather information for smuggling detection.
    
    Performs various probes to understand:
    - Server stack (front-end/back-end)
    - HTTP parsing behavior
    - Header handling quirks
    
    Example:
        profiler = TargetProfiler()
        profile = profiler.profile("https://example.com")
        
        print(f"Servers: {profile.detected_servers}")
        print(f"Behind CDN: {profile.is_behind_cdn}")
        print(f"Risk: {profile.risk_level}")
    """
    
    # Known CDN/Proxy indicators
    CDN_HEADERS = {
        "cf-ray": ServerType.CLOUDFLARE,
        "cf-cache-status": ServerType.CLOUDFLARE,
        "x-amz-cf-id": ServerType.AWS,
        "x-amz-cf-pop": ServerType.AWS,
        "x-cache": None,  # Generic cache indicator
        "x-served-by": ServerType.FASTLY,
        "x-fastly-request-id": ServerType.FASTLY,
        "akamai-grn": ServerType.AKAMAI,
        "x-akamai-transformed": ServerType.AKAMAI,
        "x-varnish": ServerType.VARNISH,
    }
    
    def __init__(self, timeout: float = 10.0, verify_ssl: bool = True):
        """
        Initialize profiler.
        
        Args:
            timeout: Request timeout
            verify_ssl: Verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.parser = HTTPResponseParser()
        
    def profile(self, url: str) -> ServerProfile:
        """
        Profile a target URL.
        
        Args:
            url: Target URL
            
        Returns:
            ServerProfile with gathered information
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        profile = ServerProfile(
            hostname=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            uses_ssl=parsed.scheme == "https"
        )
        
        try:
            # Basic probe
            self._probe_basic(profile)
            
            # Check for proxies/CDNs
            self._detect_proxies(profile)
            
            # Test HTTP capabilities
            self._test_capabilities(profile)
            
            # Test header handling
            self._test_header_handling(profile)
            
        except Exception as e:
            profile.add_hint(f"Profiling error: {e}")
            
        return profile
    
    def _probe_basic(self, profile: ServerProfile):
        """Send basic request and analyze response"""
        client = RawHTTPClient(
            host=profile.hostname,
            port=profile.port,
            use_ssl=profile.uses_ssl,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )
        
        try:
            client.connect()
            response_bytes, stats = client.send_request(
                method="GET",
                path="/",
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                }
            )
            
            response = self.parser.parse(response_bytes)
            
            # Extract server header
            profile.server_header = response.get_header("Server")
            
            # Detect server from header
            self._identify_server(profile, response)
            
            # Check connection behavior
            connection = response.get_header("Connection", "").lower()
            profile.supports_keep_alive = "close" not in connection
            
            # Record timing
            profile.connection_timeout = stats.total_time
            
        finally:
            client.close()
    
    def _identify_server(self, profile: ServerProfile, response: HTTPResponse):
        """Identify server from response headers"""
        # Check Server header
        server = profile.server_header.lower()
        
        for server_type, signatures in SERVER_SIGNATURES.items():
            for sig in signatures:
                if sig in server:
                    try:
                        profile.detected_servers.add(ServerType(server_type))
                    except ValueError:
                        pass
                    break
                    
        # Check Via header for proxies
        via = response.get_header("Via", "").lower()
        if via:
            profile.is_behind_proxy = True
            for server_type, signatures in SERVER_SIGNATURES.items():
                for sig in signatures:
                    if sig in via:
                        try:
                            profile.detected_servers.add(ServerType(server_type))
                        except ValueError:
                            pass
                            
    def _detect_proxies(self, profile: ServerProfile):
        """Detect if target is behind proxy/CDN"""
        client = RawHTTPClient(
            host=profile.hostname,
            port=profile.port,
            use_ssl=profile.uses_ssl,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )
        
        try:
            client.connect()
            response_bytes, _ = client.send_request(
                method="GET",
                path="/",
                headers={"Host": profile.hostname}
            )
            
            response = self.parser.parse(response_bytes)
            
            # Check for CDN/proxy headers
            for header_name, server_type in self.CDN_HEADERS.items():
                if response.get_header(header_name):
                    profile.is_behind_cdn = True
                    if server_type:
                        profile.detected_servers.add(server_type)
                    profile.add_hint(f"CDN header detected: {header_name}")
                    
            # Check for X-Forwarded headers (indicates proxy)
            if response.get_header("X-Forwarded-For") or \
               response.get_header("X-Forwarded-Proto"):
                profile.is_behind_proxy = True
                profile.add_hint("X-Forwarded headers present")
                
        finally:
            client.close()
    
    def _test_capabilities(self, profile: ServerProfile):
        """Test HTTP capabilities"""
        client = RawHTTPClient(
            host=profile.hostname,
            port=profile.port,
            use_ssl=profile.uses_ssl,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )
        
        try:
            client.connect()
            
            # Test chunked encoding
            chunked_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {profile.hostname}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Type: text/plain\r\n"
                f"\r\n"
                f"5\r\n"
                f"hello\r\n"
                f"0\r\n"
                f"\r\n"
            )
            
            response_bytes, _ = client.send_raw(chunked_request.encode())
            response = self.parser.parse(response_bytes)
            
            # If we get 400/411/501, chunked may not be supported
            if response.status_code in [400, 411, 501]:
                profile.supports_chunked = False
                profile.add_hint("Chunked encoding may not be supported")
            else:
                profile.supports_chunked = True
                
        except Exception as e:
            profile.add_hint(f"Capability test error: {e}")
        finally:
            client.close()
    
    def _test_header_handling(self, profile: ServerProfile):
        """Test how server handles unusual headers"""
        client = RawHTTPClient(
            host=profile.hostname,
            port=profile.port,
            use_ssl=profile.uses_ssl,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )
        
        try:
            client.connect()
            
            # Test duplicate Content-Length
            dup_cl_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {profile.hostname}\r\n"
                f"Content-Length: 5\r\n"
                f"Content-Length: 10\r\n"
                f"Content-Type: text/plain\r\n"
                f"\r\n"
                f"hello"
            )
            
            response_bytes, _ = client.send_raw(dup_cl_request.encode())
            response = self.parser.parse(response_bytes)
            
            # If server accepts this, duplicate headers are allowed
            if response.status_code != 400:
                profile.allows_duplicate_headers = True
                profile.add_hint("Server accepts duplicate Content-Length headers - HIGH RISK")
                
        except Exception:
            pass
        finally:
            client.close()
            
    def quick_profile(self, url: str) -> Dict:
        """
        Quick profile returning just essential info.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with key profile info
        """
        profile = self.profile(url)
        
        return {
            "hostname": profile.hostname,
            "port": profile.port,
            "ssl": profile.uses_ssl,
            "server": profile.server_header,
            "servers_detected": [s.value for s in profile.detected_servers],
            "behind_proxy": profile.is_behind_proxy,
            "behind_cdn": profile.is_behind_cdn,
            "risk_level": profile.risk_level,
            "hints": profile.hints
        }
