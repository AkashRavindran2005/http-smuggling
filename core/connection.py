"""
Raw Socket HTTP Client

This module provides a low-level HTTP client using raw sockets,
giving full control over the HTTP request format (essential for smuggling).

Key Features:
- No HTTP library abstractions
- Full control over headers and body
- Persistent connection support
- TLS/SSL support
- Chunked encoding support
"""

import socket
import ssl
import time
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from urllib.parse import urlparse

from config import DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT


class ConnectionError(Exception):
    """Custom exception for connection errors"""
    pass


@dataclass
class ConnectionStats:
    """Statistics about a connection"""
    connect_time: float = 0.0
    first_byte_time: float = 0.0
    total_time: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0


class RawHTTPClient:
    """
    Raw socket-based HTTP client for precise control over requests.
    
    This client bypasses standard HTTP libraries to allow:
    - Malformed headers
    - Conflicting Content-Length/Transfer-Encoding
    - Custom line endings
    - Precise timing measurements
    
    Example:
        client = RawHTTPClient("example.com", 443, use_ssl=True)
        client.connect()
        response, stats = client.send_request(method="POST", path="/", body="test")
        client.close()
    """
    
    def __init__(
        self,
        host: str,
        port: int = None,
        use_ssl: bool = False,
        timeout: float = 10.0,
        verify_ssl: bool = True
    ):
        """
        Initialize the HTTP client.
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 80 for HTTP, 443 for HTTPS)
            use_ssl: Whether to use TLS/SSL
            timeout: Socket timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.host = host
        self.port = port or (DEFAULT_HTTPS_PORT if use_ssl else DEFAULT_HTTP_PORT)
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self.socket: Optional[socket.socket] = None
        self.ssl_socket: Optional[ssl.SSLSocket] = None
        self.connected = False
        
    @classmethod
    def from_url(cls, url: str, **kwargs) -> "RawHTTPClient":
        """
        Create a client from a URL string.
        
        Args:
            url: Full URL (e.g., https://example.com:8443)
            **kwargs: Additional arguments passed to __init__
            
        Returns:
            Configured RawHTTPClient instance
        """
        parsed = urlparse(url)
        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)
        
        return cls(
            host=parsed.hostname,
            port=port,
            use_ssl=use_ssl,
            **kwargs
        )
    
    def connect(self) -> float:
        """
        Establish connection to the target.
        
        Returns:
            Connection time in seconds
            
        Raises:
            ConnectionError: If connection fails
        """
        start_time = time.time()
        
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            
            # Connect to target
            self.socket.connect((self.host, self.port))
            
            # Wrap with SSL if needed
            if self.use_ssl:
                context = ssl.create_default_context()
                if not self.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                self.ssl_socket = context.wrap_socket(
                    self.socket, 
                    server_hostname=self.host
                )
                
            self.connected = True
            return time.time() - start_time
            
        except socket.timeout:
            raise ConnectionError(f"Connection timed out to {self.host}:{self.port}")
        except socket.error as e:
            raise ConnectionError(f"Socket error: {e}")
        except ssl.SSLError as e:
            raise ConnectionError(f"SSL error: {e}")
    
    def _get_socket(self) -> socket.socket:
        """Get the active socket (SSL or plain)"""
        if self.use_ssl and self.ssl_socket:
            return self.ssl_socket
        return self.socket
    
    def send_raw(self, data: bytes) -> Tuple[bytes, ConnectionStats]:
        """
        Send raw bytes and receive response.
        
        This is the lowest-level send method, giving complete control
        over what bytes are sent.
        
        Args:
            data: Raw bytes to send
            
        Returns:
            Tuple of (response_bytes, connection_stats)
            
        Raises:
            ConnectionError: If not connected or send fails
        """
        if not self.connected:
            raise ConnectionError("Not connected. Call connect() first.")
            
        stats = ConnectionStats()
        sock = self._get_socket()
        
        # Send data
        start_time = time.time()
        sock.sendall(data)
        stats.bytes_sent = len(data)
        
        # Receive response
        response = b""
        first_byte_received = False
        
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                    
                if not first_byte_received:
                    stats.first_byte_time = time.time() - start_time
                    first_byte_received = True
                    
                response += chunk
                
                # Check for end of response (simple heuristic)
                # In production, parse Content-Length or chunked encoding
                if b"\r\n\r\n" in response:
                    # Check if we have full response
                    header_end = response.find(b"\r\n\r\n")
                    headers = response[:header_end].decode("utf-8", errors="ignore")
                    
                    # Look for Content-Length
                    if "Content-Length:" in headers:
                        for line in headers.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                content_length = int(line.split(":")[1].strip())
                                body_start = header_end + 4
                                if len(response) >= body_start + content_length:
                                    break
                    # For chunked, look for 0\r\n\r\n
                    elif b"0\r\n\r\n" in response:
                        break
                        
        except socket.timeout:
            # Timeout might be intentional for desync detection
            pass
            
        stats.total_time = time.time() - start_time
        stats.bytes_received = len(response)
        
        return response, stats
    
    def send_request(
        self,
        method: str = "GET",
        path: str = "/",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        raw_request: Optional[str] = None,
        use_crlf: bool = True
    ) -> Tuple[bytes, ConnectionStats]:
        """
        Send an HTTP request with fine-grained control.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            headers: Dictionary of headers
            body: Request body
            raw_request: If provided, send this exact string (overrides other args)
            use_crlf: Use CRLF line endings (True) or LF only (False)
            
        Returns:
            Tuple of (response_bytes, connection_stats)
        """
        if raw_request:
            return self.send_raw(raw_request.encode("utf-8"))
            
        line_ending = "\r\n" if use_crlf else "\n"
        
        # Build request line
        request = f"{method} {path} HTTP/1.1{line_ending}"
        
        # Add Host header if not present
        if headers is None:
            headers = {}
        if "Host" not in headers:
            headers["Host"] = self.host
            
        # Add headers
        for name, value in headers.items():
            request += f"{name}: {value}{line_ending}"
            
        # End headers
        request += line_ending
        
        # Add body
        if body:
            request += body
            
        return self.send_raw(request.encode("utf-8"))
    
    def send_smuggle_probe(
        self,
        prefix_request: str,
        smuggled_request: str,
        technique: str = "cl-te"
    ) -> Tuple[bytes, ConnectionStats]:
        """
        Send a smuggling probe with prefix and smuggled requests.
        
        Args:
            prefix_request: The visible request (seen by front-end)
            smuggled_request: The hidden request (interpreted by back-end)
            technique: Smuggling technique (cl-te, te-cl, te-te)
            
        Returns:
            Tuple of (response_bytes, connection_stats)
        """
        # Combine requests based on technique
        if technique == "cl-te":
            # Front-end uses CL, back-end uses TE
            # We craft CL to include part of smuggled request
            combined = prefix_request + smuggled_request
        elif technique == "te-cl":
            # Front-end uses TE, back-end uses CL  
            combined = prefix_request + smuggled_request
        else:
            combined = prefix_request + smuggled_request
            
        return self.send_raw(combined.encode("utf-8"))
    
    def close(self):
        """Close the connection"""
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except:
                pass
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False
        
    def __enter__(self):
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Convenience functions
def quick_request(
    url: str, 
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    timeout: float = 10.0
) -> Tuple[bytes, ConnectionStats]:
    """
    Make a quick one-off request.
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers
        body: Request body
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (response_bytes, connection_stats)
    """
    parsed = urlparse(url)
    with RawHTTPClient.from_url(url, timeout=timeout) as client:
        return client.send_request(
            method=method,
            path=parsed.path or "/",
            headers=headers,
            body=body
        )
