"""
HTTP Response Parser

Parses raw HTTP responses into structured data.
Handles edge cases and malformed responses gracefully.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class HTTPResponse:
    """Structured HTTP response"""
    # Status line components
    http_version: str = "HTTP/1.1"
    status_code: int = 0
    status_message: str = ""
    
    # Headers (preserving order and duplicates)
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: List[Tuple[str, str]] = field(default_factory=list)
    
    # Body
    body: bytes = b""
    
    # Raw data
    raw: bytes = b""
    
    # Parsing metadata
    is_chunked: bool = False
    content_length: Optional[int] = None
    has_content_length: bool = False
    has_transfer_encoding: bool = False
    
    # Potential smuggling indicators
    multiple_content_length: bool = False
    conflicting_headers: bool = False
    
    def get_header(self, name: str, default: str = "") -> str:
        """Get header value (case-insensitive)"""
        name_lower = name.lower()
        for key, value in self.headers.items():
            if key.lower() == name_lower:
                return value
        return default
    
    def get_all_headers(self, name: str) -> List[str]:
        """Get all values for a header (handles duplicates)"""
        name_lower = name.lower()
        return [v for k, v in self.raw_headers if k.lower() == name_lower]
    
    @property
    def is_success(self) -> bool:
        """Check if response indicates success (2xx)"""
        return 200 <= self.status_code < 300
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx)"""
        return 300 <= self.status_code < 400
    
    @property
    def is_error(self) -> bool:
        """Check if response indicates error (4xx or 5xx)"""
        return self.status_code >= 400


class HTTPResponseParser:
    """
    Parser for raw HTTP responses.
    
    Designed to handle:
    - Standard responses
    - Chunked transfer encoding
    - Malformed responses
    - Multiple responses in one stream (pipelining)
    
    Example:
        parser = HTTPResponseParser()
        response = parser.parse(raw_bytes)
        print(f"Status: {response.status_code}")
        print(f"Body: {response.body}")
    """
    
    # Regex patterns
    STATUS_LINE_PATTERN = re.compile(
        rb'^(HTTP/[\d.]+)\s+(\d+)\s*(.*?)\r?\n',
        re.IGNORECASE
    )
    
    HEADER_PATTERN = re.compile(
        rb'^([^\s:]+)\s*:\s*(.*)$'
    )
    
    def __init__(self, strict: bool = False):
        """
        Initialize parser.
        
        Args:
            strict: If True, raise exceptions on malformed responses
        """
        self.strict = strict
        
    def parse(self, raw_response: bytes) -> HTTPResponse:
        """
        Parse a raw HTTP response.
        
        Args:
            raw_response: Raw bytes of HTTP response
            
        Returns:
            Parsed HTTPResponse object
        """
        response = HTTPResponse(raw=raw_response)
        
        if not raw_response:
            return response
            
        try:
            # Split headers and body
            if b"\r\n\r\n" in raw_response:
                header_section, body = raw_response.split(b"\r\n\r\n", 1)
            elif b"\n\n" in raw_response:
                header_section, body = raw_response.split(b"\n\n", 1)
            else:
                header_section = raw_response
                body = b""
                
            # Parse status line
            lines = header_section.split(b"\r\n")
            if not lines:
                lines = header_section.split(b"\n")
                
            if lines:
                self._parse_status_line(lines[0], response)
                
            # Parse headers
            content_length_values = []
            transfer_encoding_values = []
            
            for line in lines[1:]:
                if not line:
                    continue
                    
                header_match = self.HEADER_PATTERN.match(line)
                if header_match:
                    name = header_match.group(1).decode("utf-8", errors="ignore")
                    value = header_match.group(2).decode("utf-8", errors="ignore").strip()
                    
                    # Store in both formats
                    response.headers[name] = value
                    response.raw_headers.append((name, value))
                    
                    # Track important headers
                    name_lower = name.lower()
                    if name_lower == "content-length":
                        response.has_content_length = True
                        content_length_values.append(value)
                        try:
                            response.content_length = int(value)
                        except ValueError:
                            pass
                            
                    elif name_lower == "transfer-encoding":
                        response.has_transfer_encoding = True
                        transfer_encoding_values.append(value)
                        if "chunked" in value.lower():
                            response.is_chunked = True
                            
            # Check for smuggling indicators
            if len(content_length_values) > 1:
                response.multiple_content_length = True
                
            if response.has_content_length and response.has_transfer_encoding:
                response.conflicting_headers = True
                
            # Parse body
            if response.is_chunked:
                response.body = self._parse_chunked_body(body)
            else:
                response.body = body
                
        except Exception as e:
            if self.strict:
                raise
            # In non-strict mode, return partial response
            
        return response
    
    def _parse_status_line(self, line: bytes, response: HTTPResponse):
        """Parse the HTTP status line"""
        match = self.STATUS_LINE_PATTERN.match(line + b"\n")
        if match:
            response.http_version = match.group(1).decode("utf-8", errors="ignore")
            response.status_code = int(match.group(2))
            response.status_message = match.group(3).decode("utf-8", errors="ignore").strip()
        else:
            # Try simpler parsing
            parts = line.split(b" ", 2)
            if len(parts) >= 2:
                response.http_version = parts[0].decode("utf-8", errors="ignore")
                try:
                    response.status_code = int(parts[1])
                except ValueError:
                    pass
                if len(parts) > 2:
                    response.status_message = parts[2].decode("utf-8", errors="ignore")
                    
    def _parse_chunked_body(self, body: bytes) -> bytes:
        """Parse chunked transfer encoding body"""
        result = b""
        remaining = body
        
        while remaining:
            # Find chunk size line
            if b"\r\n" in remaining:
                size_line, remaining = remaining.split(b"\r\n", 1)
            elif b"\n" in remaining:
                size_line, remaining = remaining.split(b"\n", 1)
            else:
                break
                
            # Parse chunk size (may have extensions after semicolon)
            size_str = size_line.split(b";")[0].strip()
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break
                
            if chunk_size == 0:
                # End of chunks
                break
                
            # Extract chunk data
            if len(remaining) >= chunk_size:
                result += remaining[:chunk_size]
                remaining = remaining[chunk_size:]
                
                # Skip trailing CRLF
                if remaining.startswith(b"\r\n"):
                    remaining = remaining[2:]
                elif remaining.startswith(b"\n"):
                    remaining = remaining[1:]
            else:
                # Incomplete chunk
                result += remaining
                break
                
        return result
    
    def parse_multiple(self, raw_data: bytes) -> List[HTTPResponse]:
        """
        Parse multiple HTTP responses from pipelined data.
        
        Useful for detecting smuggled responses.
        
        Args:
            raw_data: Raw bytes potentially containing multiple responses
            
        Returns:
            List of parsed HTTPResponse objects
        """
        responses = []
        remaining = raw_data
        
        while remaining:
            # Find next response start
            if not remaining.startswith(b"HTTP"):
                # Skip any leading garbage
                http_start = remaining.find(b"HTTP")
                if http_start == -1:
                    break
                remaining = remaining[http_start:]
                
            # Try to find response boundary
            # This is heuristic - look for next HTTP status line
            next_http = remaining[1:].find(b"HTTP/")
            
            if next_http != -1:
                response_bytes = remaining[:next_http + 1]
                remaining = remaining[next_http + 1:]
            else:
                response_bytes = remaining
                remaining = b""
                
            response = self.parse(response_bytes)
            if response.status_code > 0:
                responses.append(response)
                
        return responses


def detect_smuggling_indicators(response: HTTPResponse) -> Dict[str, bool]:
    """
    Analyze response for potential smuggling indicators.
    
    Args:
        response: Parsed HTTP response
        
    Returns:
        Dictionary of indicator names to boolean values
    """
    indicators = {
        "multiple_content_length": response.multiple_content_length,
        "conflicting_cl_te": response.conflicting_headers,
        "chunked_encoding": response.is_chunked,
        "unusual_status": response.status_code in [400, 501, 505],
        "connection_close": "close" in response.get_header("Connection", "").lower(),
    }
    
    # Check for chunked + content-length (should not happen per RFC)
    if response.is_chunked and response.content_length is not None:
        indicators["both_cl_and_chunked"] = True
    else:
        indicators["both_cl_and_chunked"] = False
        
    return indicators
