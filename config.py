"""
Configuration settings for HTTP Smuggling Detection Tool
"""

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class TechniqueType(Enum):
    """Smuggling technique types"""
    CL_TE = "cl-te"
    TE_CL = "te-cl"
    TE_TE = "te-te"
    CL_CL = "cl-cl"
    H2_CL = "h2-cl"
    H2_TE = "h2-te"


class Verbosity(Enum):
    """Output verbosity levels"""
    QUIET = 0
    NORMAL = 1
    VERBOSE = 2
    DEBUG = 3


@dataclass
class TimingConfig:
    """Timing-related configuration"""
    # Base timeout for connections (seconds)
    connection_timeout: float = 10.0
    
    # Read timeout for responses (seconds)
    read_timeout: float = 10.0
    
    # Delay threshold for desync detection (seconds)
    # If response takes longer than this, possible desync
    desync_threshold: float = 5.0
    
    # Number of timing samples for accuracy
    timing_samples: int = 3
    
    # Delay between requests to avoid rate limiting
    request_delay: float = 0.5


@dataclass
class PayloadConfig:
    """Payload generation configuration"""
    # Use obfuscation techniques
    use_obfuscation: bool = True
    
    # Maximum payload size (bytes)
    max_payload_size: int = 8192
    
    # Custom headers to include
    custom_headers: dict = field(default_factory=dict)
    
    # User-Agent string
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class ScanConfig:
    """Main scanning configuration"""
    # Target URL
    target: str = ""
    
    # Techniques to test
    techniques: List[TechniqueType] = field(default_factory=lambda: [
        TechniqueType.CL_TE,
        TechniqueType.TE_CL,
        TechniqueType.TE_TE
    ])
    
    # Number of parallel connections
    concurrency: int = 1
    
    # Follow redirects
    follow_redirects: bool = False
    
    # Maximum redirect depth
    max_redirects: int = 3
    
    # Verify SSL certificates
    verify_ssl: bool = True
    
    # Output verbosity
    verbosity: Verbosity = Verbosity.NORMAL
    
    # Report output path
    report_path: Optional[str] = None
    
    # Timing configuration
    timing: TimingConfig = field(default_factory=TimingConfig)
    
    # Payload configuration
    payload: PayloadConfig = field(default_factory=PayloadConfig)


# Transfer-Encoding obfuscation variants
TE_OBFUSCATIONS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding: chunked",          # Standard
    "Transfer-Encoding : chunked",          # Space before colon
    "Transfer-Encoding: chunked",           # Tab after colon
    "Transfer-Encoding:\tchunked",          # Tab instead of space
    "Transfer-Encoding: chunked\r\n",       # Extra CRLF handling
    " Transfer-Encoding: chunked",          # Leading space
    "Transfer-Encoding: chunked ",          # Trailing space
    "Transfer-Encoding: ChUnKeD",           # Mixed case
    "Transfer-Encoding: CHUNKED",           # Uppercase
    "Transfer-encoding: chunked",           # Lowercase header
    "TRANSFER-ENCODING: chunked",           # Uppercase header
    "Transfer-Encoding: x]chunked",         # Invalid prefix (some parsers strip)
    "Transfer-Encoding: chunked, identity", # Multiple encodings
    "Transfer-Encoding: identity, chunked", # Reverse order
    "Transfer-Encoding:\n chunked",         # Line folding (obsolete)
    "X-Ignored: x\nTransfer-Encoding: chunked",  # Header injection attempt
    "Transfer-Encoding: chunkedx",          # Suffix (may be stripped)
    "Transfer-Encoding: xchunked",          # Prefix (may be stripped)
]


# Common server signatures for fingerprinting
SERVER_SIGNATURES = {
    "nginx": ["nginx", "openresty"],
    "apache": ["apache", "httpd"],
    "iis": ["microsoft-iis", "iis"],
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai", "akamaighost"],
    "aws": ["amazons3", "awselb", "cloudfront"],
    "fastly": ["fastly"],
    "varnish": ["varnish"],
    "haproxy": ["haproxy"],
    "gunicorn": ["gunicorn"],
    "uvicorn": ["uvicorn"],
    "tomcat": ["tomcat", "coyote"],
    "jetty": ["jetty"],
    "nodejs": ["node", "express"],
    "golang": ["go-http-server"],
}


# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


# Default ports
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
