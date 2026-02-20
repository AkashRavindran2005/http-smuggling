"""
HTTP Request Smuggling Detector

Core detection engine that tests for various smuggling techniques:
- CL.TE (Content-Length vs Transfer-Encoding)
- TE.CL (Transfer-Encoding vs Content-Length)
- TE.TE (Transfer-Encoding obfuscation)
- H2.CL/H2.TE (HTTP/2 downgrade)
"""

from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import time

from core.connection import RawHTTPClient, ConnectionError
from core.parser import HTTPResponseParser, HTTPResponse
from core.timing import TimingAnalyzer, TimingResult
from config import TechniqueType, TE_OBFUSCATIONS
from payloads.generator import PayloadGenerator


class Confidence(Enum):
    """Detection confidence levels"""
    CONFIRMED = "confirmed"      # Strong evidence of vulnerability
    PROBABLE = "probable"        # High likelihood
    POSSIBLE = "possible"        # Some indicators present
    UNLIKELY = "unlikely"        # Weak or no indicators
    ERROR = "error"              # Detection failed


@dataclass
class DetectionResult:
    """Result of a smuggling detection attempt"""
    technique: TechniqueType
    vulnerable: bool
    confidence: Confidence
    
    # Evidence
    timing_delay: float = 0.0
    response_anomaly: str = ""
    smuggled_response: Optional[HTTPResponse] = None
    
    # Request/response data for reporting
    request_sent: str = ""
    response_received: str = ""
    
    # Additional context
    details: str = ""
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for reporting"""
        return {
            "technique": self.technique.value,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence.value,
            "timing_delay": self.timing_delay,
            "response_anomaly": self.response_anomaly,
            "details": self.details,
            "recommendations": self.recommendations
        }


class SmuggleDetector:
    """
    HTTP Request Smuggling Detection Engine.
    
    Tests targets for various smuggling vulnerabilities using:
    1. Timing-based detection (delayed responses indicate desync)
    2. Differential responses (different handling of payloads)
    3. Content reflection (smuggled content appears in response)
    
    Example:
        detector = SmuggleDetector("https://example.com")
        results = detector.scan_all()
        
        for result in results:
            if result.vulnerable:
                print(f"VULNERABLE: {result.technique.value}")
                print(f"Confidence: {result.confidence.value}")
    """
    
    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        desync_threshold: float = 5.0
    ):
        """
        Initialize detector.
        
        Args:
            target_url: Target URL to test
            timeout: Request timeout
            verify_ssl: Verify SSL certificates
            desync_threshold: Timing threshold for desync detection (seconds)
        """
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_ssl = parsed.scheme == "https"
        self.path = parsed.path or "/"
        
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.desync_threshold = desync_threshold
        
        self.parser = HTTPResponseParser()
        self.payload_gen = PayloadGenerator(self.host)
        self.timing = TimingAnalyzer(threshold=desync_threshold, timeout=timeout)
        
    def _create_client(self) -> RawHTTPClient:
        """Create a new HTTP client"""
        return RawHTTPClient(
            host=self.host,
            port=self.port,
            use_ssl=self.use_ssl,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )
        
    def scan_all(self, techniques: Optional[List[TechniqueType]] = None) -> List[DetectionResult]:
        """
        Scan for all smuggling techniques.
        
        Args:
            techniques: Specific techniques to test (default: all)
            
        Returns:
            List of DetectionResult objects
        """
        if techniques is None:
            techniques = [
                TechniqueType.CL_TE,
                TechniqueType.TE_CL,
                TechniqueType.TE_TE
            ]
            
        results = []
        
        for technique in techniques:
            result = self.detect(technique)
            results.append(result)
            
            # Small delay between tests
            time.sleep(0.5)
            
        return results
    
    def detect(self, technique: TechniqueType) -> DetectionResult:
        """
        Detect a specific smuggling technique.
        
        Args:
            technique: The technique to test
            
        Returns:
            DetectionResult with findings
        """
        try:
            if technique == TechniqueType.CL_TE:
                return self._detect_cl_te()
            elif technique == TechniqueType.TE_CL:
                return self._detect_te_cl()
            elif technique == TechniqueType.TE_TE:
                return self._detect_te_te()
            else:
                return DetectionResult(
                    technique=technique,
                    vulnerable=False,
                    confidence=Confidence.ERROR,
                    details=f"Technique {technique.value} not implemented"
                )
        except ConnectionError as e:
            return DetectionResult(
                technique=technique,
                vulnerable=False,
                confidence=Confidence.ERROR,
                details=f"Connection error: {e}"
            )
        except Exception as e:
            return DetectionResult(
                technique=technique,
                vulnerable=False,
                confidence=Confidence.ERROR,
                details=f"Detection error: {e}"
            )
    
    def _detect_cl_te(self) -> DetectionResult:
        """
        Detect CL.TE vulnerability.
        
        This technique exploits when:
        - Front-end uses Content-Length
        - Back-end uses Transfer-Encoding
        
        Detection method:
        Send a request where CL says body is complete, but TE says
        there's more data. If back-end times out waiting, it's vulnerable.
        """
        # Generate payload
        payload = self.payload_gen.cl_te_timing_probe(self.path)
        
        # Establish baseline timing
        self.timing.clear_baseline()
        for _ in range(3):
            client = self._create_client()
            try:
                client.connect()
                _, stats = client.send_request(
                    method="GET",
                    path=self.path,
                    headers={"Host": self.host, "Connection": "close"}
                )
                from core.timing import TimingSample
                self.timing.add_baseline(TimingSample(
                    request_time=0,
                    first_byte_time=stats.first_byte_time,
                    total_time=stats.total_time
                ))
            finally:
                client.close()
            time.sleep(0.2)
        
        # Send probe
        client = self._create_client()
        try:
            client.connect()
            start = time.time()
            response_bytes, stats = client.send_raw(payload.encode())
            elapsed = time.time() - start
            
            response = self.parser.parse(response_bytes)
            
            # Analyze timing
            from core.timing import TimingSample
            probe_sample = TimingSample(
                request_time=0,
                first_byte_time=stats.first_byte_time,
                total_time=stats.total_time,
                timed_out=elapsed >= self.timeout
            )
            
            analysis = self.timing.analyze(probe_sample)
            
            # Determine vulnerability
            if analysis.result == TimingResult.TIMEOUT:
                return DetectionResult(
                    technique=TechniqueType.CL_TE,
                    vulnerable=True,
                    confidence=Confidence.CONFIRMED,
                    timing_delay=elapsed,
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details="Request timed out - back-end appears to be waiting for chunked data",
                    recommendations=[
                        "Configure back-end to normalize Transfer-Encoding handling",
                        "Ensure front-end and back-end agree on Content-Length vs Transfer-Encoding priority",
                        "Consider rejecting requests with both headers"
                    ]
                )
            elif analysis.result == TimingResult.DELAYED:
                return DetectionResult(
                    technique=TechniqueType.CL_TE,
                    vulnerable=True,
                    confidence=Confidence.PROBABLE,
                    timing_delay=stats.total_time,
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details=f"Significant delay detected ({stats.total_time:.2f}s vs baseline {analysis.mean_total:.2f}s)",
                    recommendations=[
                        "Further manual testing recommended",
                        "Verify by attempting request hijacking"
                    ]
                )
            else:
                return DetectionResult(
                    technique=TechniqueType.CL_TE,
                    vulnerable=False,
                    confidence=Confidence.UNLIKELY,
                    timing_delay=stats.total_time,
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details="No timing anomaly detected"
                )
                
        finally:
            client.close()
    
    def _detect_te_cl(self) -> DetectionResult:
        """
        Detect TE.CL vulnerability.
        
        This technique exploits when:
        - Front-end uses Transfer-Encoding
        - Back-end uses Content-Length
        
        Detection method:
        Send a chunked request where the chunks contain more data
        than Content-Length indicates. If back-end processes extra
        data as new request, it's vulnerable.
        """
        # Generate payload
        payload = self.payload_gen.te_cl_timing_probe(self.path)
        
        # Establish baseline
        self.timing.clear_baseline()
        for _ in range(3):
            client = self._create_client()
            try:
                client.connect()
                _, stats = client.send_request(
                    method="GET",
                    path=self.path,
                    headers={"Host": self.host, "Connection": "close"}
                )
                from core.timing import TimingSample
                self.timing.add_baseline(TimingSample(
                    request_time=0,
                    first_byte_time=stats.first_byte_time,
                    total_time=stats.total_time
                ))
            finally:
                client.close()
            time.sleep(0.2)
        
        # Send probe
        client = self._create_client()
        try:
            client.connect()
            start = time.time()
            response_bytes, stats = client.send_raw(payload.encode())
            elapsed = time.time() - start
            
            response = self.parser.parse(response_bytes)
            
            # For TE.CL, look for error responses indicating smuggled request was processed
            if response.status_code in [400, 405, 501]:
                return DetectionResult(
                    technique=TechniqueType.TE_CL,
                    vulnerable=True,
                    confidence=Confidence.PROBABLE,
                    response_anomaly=f"Received {response.status_code} - smuggled request may have been processed",
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details="Back-end appears to process smuggled prefix",
                    recommendations=[
                        "Configure front-end to normalize Content-Length handling",
                        "Reject requests with both CL and TE headers"
                    ]
                )
            elif elapsed >= self.timeout * 0.8:
                return DetectionResult(
                    technique=TechniqueType.TE_CL,
                    vulnerable=True,
                    confidence=Confidence.POSSIBLE,
                    timing_delay=elapsed,
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details="Request delayed significantly"
                )
            else:
                return DetectionResult(
                    technique=TechniqueType.TE_CL,
                    vulnerable=False,
                    confidence=Confidence.UNLIKELY,
                    request_sent=payload,
                    response_received=response_bytes.decode("utf-8", errors="ignore")[:500],
                    details="No vulnerability indicators detected"
                )
                
        finally:
            client.close()
    
    def _detect_te_te(self) -> DetectionResult:
        """
        Detect TE.TE vulnerability.
        
        Both front-end and back-end use Transfer-Encoding, but
        obfuscation tricks cause one to ignore it.
        
        Tests various TE header obfuscations.
        """
        results = []
        
        for i, te_variant in enumerate(TE_OBFUSCATIONS[:5]):  # Test first 5 variants
            payload = self.payload_gen.te_te_probe(self.path, te_variant)
            
            client = self._create_client()
            try:
                client.connect()
                response_bytes, stats = client.send_raw(payload.encode())
                response = self.parser.parse(response_bytes)
                
                # Check for indicators
                if response.status_code in [400, 405, 501]:
                    results.append({
                        "variant": te_variant,
                        "status": response.status_code,
                        "possible_vuln": True
                    })
                    
            except Exception as e:
                results.append({
                    "variant": te_variant,
                    "error": str(e),
                    "possible_vuln": False
                })
            finally:
                client.close()
                
            time.sleep(0.2)
        
        # Analyze results
        vuln_variants = [r for r in results if r.get("possible_vuln")]
        
        if vuln_variants:
            return DetectionResult(
                technique=TechniqueType.TE_TE,
                vulnerable=True,
                confidence=Confidence.POSSIBLE,
                details=f"Found {len(vuln_variants)} potentially vulnerable TE variants",
                recommendations=[
                    "Test each variant manually for exploitation",
                    "Normalize Transfer-Encoding header parsing"
                ]
            )
        else:
            return DetectionResult(
                technique=TechniqueType.TE_TE,
                vulnerable=False,
                confidence=Confidence.UNLIKELY,
                details="No TE obfuscation variants caused anomalies"
            )


def quick_scan(url: str) -> List[DetectionResult]:
    """
    Quick scan of a URL for all techniques.
    
    Args:
        url: Target URL
        
    Returns:
        List of DetectionResult objects
    """
    detector = SmuggleDetector(url)
    return detector.scan_all()
