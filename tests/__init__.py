"""
Tests for HTTP Smuggling Tool
"""

import pytest
from payloads.generator import PayloadGenerator


class TestPayloadGenerator:
    """Test payload generation"""
    
    @pytest.fixture
    def generator(self):
        return PayloadGenerator("example.com")
    
    def test_cl_te_timing_probe(self, generator):
        """Test CL.TE timing probe payload"""
        payload = generator.cl_te_timing_probe("/")
        
        assert "POST / HTTP/1.1" in payload
        assert "Content-Length:" in payload
        assert "Transfer-Encoding: chunked" in payload
        assert "Host: example.com" in payload
        
    def test_te_cl_timing_probe(self, generator):
        """Test TE.CL timing probe payload"""
        payload = generator.te_cl_timing_probe("/")
        
        assert "POST / HTTP/1.1" in payload
        assert "Content-Length: 6" in payload
        assert "Transfer-Encoding: chunked" in payload
        
    def test_te_te_variants(self, generator):
        """Test TE.TE variant generation"""
        variants = generator.te_te_variants("/")
        
        assert len(variants) > 5
        for v in variants:
            assert "POST / HTTP/1.1" in v
            
    def test_request_hijack_cl_te(self, generator):
        """Test request hijack payload generation"""
        payload = generator.request_hijack_payload(
            technique="cl-te",
            capture_path="/capture"
        )
        
        assert "POST /capture" in payload
        assert "Content-Length:" in payload
        
    def test_custom_payload(self, generator):
        """Test custom payload generation"""
        payload = generator.custom_payload(
            method="GET",
            path="/test",
            headers={"X-Custom": "value"},
            body="test body"
        )
        
        assert "GET /test HTTP/1.1" in payload
        assert "X-Custom: value" in payload
        assert "Host: example.com" in payload
        assert "test body" in payload


class TestPayloadStructure:
    """Test payload structure validity"""
    
    @pytest.fixture
    def generator(self):
        return PayloadGenerator("target.com", 443)
    
    def test_crlf_endings(self, generator):
        """Ensure payloads use CRLF line endings"""
        payload = generator.cl_te_timing_probe("/")
        
        # Should contain CRLF
        assert "\r\n" in payload
        
    def test_host_header_with_port(self, generator):
        """Test Host header includes port when specified"""
        payload = generator.cl_te_basic_probe("/")
        
        assert "Host: target.com:443" in payload
        
    def test_chunked_encoding_format(self, generator):
        """Test chunked encoding is properly formatted"""
        payload = generator.cl_te_basic_probe("/")
        
        # Should end with proper chunk terminator
        assert "0\r\n\r\n" in payload


class TestIntegration:
    """Integration tests (require network access)"""
    
    @pytest.mark.skip(reason="Requires network access")
    def test_scanner_connection(self):
        """Test scanner can connect to a target"""
        from scanner.detector import SmuggleDetector
        
        detector = SmuggleDetector("https://httpbin.org", timeout=5)
        # Just test that it initializes correctly
        assert detector.host == "httpbin.org"
        
    @pytest.mark.skip(reason="Requires network access")
    def test_profiler(self):
        """Test profiler can analyze a target"""
        from scanner.profiler import TargetProfiler
        
        profiler = TargetProfiler(timeout=5)
        profile = profiler.profile("https://httpbin.org")
        
        assert profile.hostname == "httpbin.org"
        assert profile.uses_ssl == True
