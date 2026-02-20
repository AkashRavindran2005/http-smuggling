"""
Timing Analysis Utilities

Provides timing-based analysis for detecting HTTP desynchronization.
Timing differentials are a key indicator of successful smuggling.
"""

import time
import statistics
from typing import List, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class TimingResult(Enum):
    """Result of timing analysis"""
    NORMAL = "normal"
    DELAYED = "delayed"
    TIMEOUT = "timeout"
    INCONCLUSIVE = "inconclusive"


@dataclass
class TimingSample:
    """Single timing measurement"""
    request_time: float      # Time to send request
    first_byte_time: float   # Time to first byte (TTFB)
    total_time: float        # Total request-response time
    timed_out: bool = False  # Whether request timed out
    error: Optional[str] = None


@dataclass
class TimingAnalysis:
    """Results of timing analysis"""
    samples: List[TimingSample]
    mean_ttfb: float
    std_ttfb: float
    mean_total: float
    std_total: float
    result: TimingResult
    confidence: float  # 0.0 to 1.0
    details: str = ""


class TimingAnalyzer:
    """
    Analyzes timing patterns to detect desynchronization.
    
    HTTP request smuggling often causes timing anomalies:
    - Delayed responses (back-end waiting for more data)
    - Timeouts (request stuck in queue)
    - Variable timing (interference with other requests)
    
    Example:
        analyzer = TimingAnalyzer(threshold=5.0)
        
        # Collect baseline
        for _ in range(3):
            sample = analyzer.measure(lambda: send_normal_request())
            analyzer.add_baseline(sample)
        
        # Test suspicious request
        test_sample = analyzer.measure(lambda: send_smuggle_probe())
        result = analyzer.analyze(test_sample)
        
        print(f"Result: {result.result.value}")
        print(f"Confidence: {result.confidence:.2%}")
    """
    
    def __init__(
        self,
        threshold: float = 5.0,
        timeout: float = 10.0,
        baseline_samples: int = 3
    ):
        """
        Initialize timing analyzer.
        
        Args:
            threshold: Time difference threshold for detecting delay (seconds)
            timeout: Request timeout (seconds)
            baseline_samples: Number of baseline samples to collect
        """
        self.threshold = threshold
        self.timeout = timeout
        self.baseline_samples = baseline_samples
        self.baseline: List[TimingSample] = []
        
    def measure(
        self,
        request_func: Callable[[], Tuple[bytes, float, float]],
    ) -> TimingSample:
        """
        Measure timing of a request.
        
        Args:
            request_func: Function that sends request and returns
                         (response, first_byte_time, total_time)
                         
        Returns:
            TimingSample with measurements
        """
        start = time.time()
        
        try:
            response, first_byte, total = request_func()
            
            return TimingSample(
                request_time=time.time() - start,
                first_byte_time=first_byte,
                total_time=total,
                timed_out=False
            )
            
        except TimeoutError:
            return TimingSample(
                request_time=self.timeout,
                first_byte_time=self.timeout,
                total_time=self.timeout,
                timed_out=True,
                error="timeout"
            )
        except Exception as e:
            return TimingSample(
                request_time=time.time() - start,
                first_byte_time=0,
                total_time=time.time() - start,
                timed_out=False,
                error=str(e)
            )
    
    def add_baseline(self, sample: TimingSample):
        """Add a sample to the baseline measurements"""
        if not sample.timed_out and sample.error is None:
            self.baseline.append(sample)
            
    def clear_baseline(self):
        """Clear baseline measurements"""
        self.baseline = []
        
    def analyze(
        self,
        test_sample: TimingSample,
        baseline: Optional[List[TimingSample]] = None
    ) -> TimingAnalysis:
        """
        Analyze a test sample against baseline.
        
        Args:
            test_sample: The timing sample to analyze
            baseline: Optional custom baseline (uses stored baseline if None)
            
        Returns:
            TimingAnalysis with results
        """
        samples = baseline or self.baseline
        
        if not samples:
            return TimingAnalysis(
                samples=[test_sample],
                mean_ttfb=test_sample.first_byte_time,
                std_ttfb=0,
                mean_total=test_sample.total_time,
                std_total=0,
                result=TimingResult.INCONCLUSIVE,
                confidence=0.0,
                details="No baseline samples available"
            )
            
        # Calculate baseline statistics
        ttfb_values = [s.first_byte_time for s in samples]
        total_values = [s.total_time for s in samples]
        
        mean_ttfb = statistics.mean(ttfb_values)
        std_ttfb = statistics.stdev(ttfb_values) if len(ttfb_values) > 1 else 0
        mean_total = statistics.mean(total_values)
        std_total = statistics.stdev(total_values) if len(total_values) > 1 else 0
        
        # Analyze test sample
        if test_sample.timed_out:
            result = TimingResult.TIMEOUT
            confidence = 0.9  # High confidence on timeout
            details = f"Request timed out (>{self.timeout}s)"
            
        elif test_sample.total_time > mean_total + self.threshold:
            # Significant delay detected
            delay = test_sample.total_time - mean_total
            result = TimingResult.DELAYED
            
            # Calculate confidence based on how far outside normal range
            z_score = delay / (std_total + 0.1)  # Avoid division by zero
            confidence = min(0.95, 0.5 + (z_score * 0.1))
            
            details = f"Response delayed by {delay:.2f}s (baseline: {mean_total:.2f}s)"
            
        elif abs(test_sample.total_time - mean_total) <= std_total * 2:
            # Within normal range
            result = TimingResult.NORMAL
            confidence = 0.8
            details = f"Response time normal ({test_sample.total_time:.2f}s, baseline: {mean_total:.2f}s)"
            
        else:
            result = TimingResult.INCONCLUSIVE
            confidence = 0.3
            details = "Timing pattern unclear"
            
        return TimingAnalysis(
            samples=samples + [test_sample],
            mean_ttfb=mean_ttfb,
            std_ttfb=std_ttfb,
            mean_total=mean_total,
            std_total=std_total,
            result=result,
            confidence=confidence,
            details=details
        )
    
    def detect_desync(
        self,
        normal_request_func: Callable,
        probe_request_func: Callable,
        num_samples: int = 3
    ) -> Tuple[bool, TimingAnalysis]:
        """
        Detect desynchronization using comparative timing.
        
        Sends normal requests to establish baseline, then probes
        for timing anomalies that indicate desync.
        
        Args:
            normal_request_func: Function to send normal request
            probe_request_func: Function to send probe request
            num_samples: Number of samples for each type
            
        Returns:
            Tuple of (is_desync_detected, analysis)
        """
        # Collect baseline
        self.clear_baseline()
        for _ in range(num_samples):
            sample = self.measure(normal_request_func)
            self.add_baseline(sample)
            time.sleep(0.1)  # Small delay between requests
            
        # Send probe
        probe_sample = self.measure(probe_request_func)
        analysis = self.analyze(probe_sample)
        
        # Desync detected if delayed or timeout
        is_desync = analysis.result in [TimingResult.DELAYED, TimingResult.TIMEOUT]
        
        return is_desync, analysis


class DifferentialTiming:
    """
    Differential timing analysis for more accurate detection.
    
    Compares timing of paired requests to detect smuggling:
    1. Normal request A, Normal request B (baseline)
    2. Smuggle probe, Victim request (test)
    
    If B is faster in pair 1 but slower in pair 2, smuggling may be occurring.
    """
    
    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        
    def analyze_pair(
        self,
        first_request_func: Callable,
        second_request_func: Callable,
        delay_between: float = 0.1
    ) -> Tuple[TimingSample, TimingSample]:
        """
        Send a pair of requests and time them.
        
        Args:
            first_request_func: First request function
            second_request_func: Second request function
            delay_between: Delay between requests
            
        Returns:
            Tuple of timing samples for both requests
        """
        # First request
        start1 = time.time()
        try:
            _, fb1, total1 = first_request_func()
            sample1 = TimingSample(
                request_time=time.time() - start1,
                first_byte_time=fb1,
                total_time=total1
            )
        except Exception as e:
            sample1 = TimingSample(0, 0, 0, error=str(e))
            
        time.sleep(delay_between)
        
        # Second request
        start2 = time.time()
        try:
            _, fb2, total2 = second_request_func()
            sample2 = TimingSample(
                request_time=time.time() - start2,
                first_byte_time=fb2,
                total_time=total2
            )
        except Exception as e:
            sample2 = TimingSample(0, 0, 0, error=str(e))
            
        return sample1, sample2
    
    def detect_interference(
        self,
        baseline_pairs: List[Tuple[TimingSample, TimingSample]],
        test_pair: Tuple[TimingSample, TimingSample]
    ) -> Tuple[bool, float, str]:
        """
        Detect if the probe request interfered with the follow-up request.
        
        Args:
            baseline_pairs: List of baseline timing pairs
            test_pair: The test timing pair (probe + follow-up)
            
        Returns:
            Tuple of (interference_detected, confidence, details)
        """
        if not baseline_pairs:
            return False, 0.0, "No baseline data"
            
        # Calculate baseline differential
        baseline_diffs = [
            pair[1].total_time - pair[0].total_time 
            for pair in baseline_pairs
            if not pair[0].error and not pair[1].error
        ]
        
        if not baseline_diffs:
            return False, 0.0, "No valid baseline pairs"
            
        mean_diff = statistics.mean(baseline_diffs)
        
        # Calculate test differential
        if test_pair[0].error or test_pair[1].error:
            return True, 0.7, "Request error during test"
            
        test_diff = test_pair[1].total_time - test_pair[0].total_time
        
        # Compare
        anomaly = test_diff - mean_diff
        
        if anomaly > self.threshold:
            return True, min(0.95, 0.5 + anomaly * 0.1), \
                f"Follow-up request delayed by {anomaly:.2f}s"
        elif test_pair[1].timed_out:
            return True, 0.9, "Follow-up request timed out"
        else:
            return False, 0.8, "No timing anomaly detected"
