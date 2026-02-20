"""
Vulnerability Report Generator

Generates detailed HTML and Markdown reports for smuggling findings.
"""

import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scanner.detector import DetectionResult, Confidence
from scanner.profiler import ServerProfile


@dataclass
class ReportMetadata:
    """Metadata for the report"""
    target: str
    scan_date: str
    scan_duration: float
    techniques_tested: List[str]
    tool_version: str = "1.0.0"


class ReportGenerator:
    """
    Generates vulnerability reports in various formats.
    
    Supports:
    - HTML reports (rich, styled)
    - Markdown reports
    - JSON reports (machine-readable)
    
    Example:
        gen = ReportGenerator()
        gen.add_profile(server_profile)
        gen.add_results(detection_results)
        gen.generate_html("report.html")
    """
    
    def __init__(self):
        self.metadata: Optional[ReportMetadata] = None
        self.profile: Optional[ServerProfile] = None
        self.results: List[DetectionResult] = []
        
    def set_metadata(
        self,
        target: str,
        scan_duration: float,
        techniques: List[str]
    ):
        """Set report metadata"""
        self.metadata = ReportMetadata(
            target=target,
            scan_date=datetime.now().isoformat(),
            scan_duration=scan_duration,
            techniques_tested=techniques
        )
        
    def add_profile(self, profile: ServerProfile):
        """Add server profile to report"""
        self.profile = profile
        
    def add_results(self, results: List[DetectionResult]):
        """Add detection results to report"""
        self.results.extend(results)
        
    def add_result(self, result: DetectionResult):
        """Add single detection result"""
        self.results.append(result)
        
    def _get_severity_color(self, confidence: Confidence) -> str:
        """Get color for severity level"""
        colors = {
            Confidence.CONFIRMED: "#dc3545",   # Red
            Confidence.PROBABLE: "#fd7e14",    # Orange
            Confidence.POSSIBLE: "#ffc107",    # Yellow
            Confidence.UNLIKELY: "#28a745",    # Green
            Confidence.ERROR: "#6c757d",       # Gray
        }
        return colors.get(confidence, "#6c757d")
    
    def _get_severity_badge(self, confidence: Confidence) -> str:
        """Get HTML badge for severity"""
        color = self._get_severity_color(confidence)
        return f'<span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 4px;">{confidence.value.upper()}</span>'
    
    def generate_html(self, output_path: str) -> str:
        """
        Generate HTML report.
        
        Args:
            output_path: Path to save HTML file
            
        Returns:
            Path to generated report
        """
        html = self._build_html()
        
        with open(output_path, 'w') as f:
            f.write(html)
            
        return output_path
    
    def _build_html(self) -> str:
        """Build HTML report content"""
        vulnerable_count = sum(1 for r in self.results if r.vulnerable)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Smuggling Scan Report</title>
    <style>
        :root {{
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --accent: #0f3460;
            --text: #eee;
            --text-muted: #aaa;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, #e94560, #0f3460);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        
        h2 {{
            font-size: 1.5rem;
            margin: 2rem 0 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent);
        }}
        
        .card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-item {{
            background: var(--accent);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-item .value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        
        .summary-item .label {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        
        .vulnerable {{ color: var(--danger); }}
        .safe {{ color: var(--success); }}
        
        .result-card {{
            border-left: 4px solid;
            margin-bottom: 1rem;
        }}
        
        .result-vulnerable {{
            border-color: var(--danger);
        }}
        
        .result-safe {{
            border-color: var(--success);
        }}
        
        .result-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}
        
        .technique-name {{
            font-size: 1.25rem;
            font-weight: bold;
        }}
        
        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        
        .details {{
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem;
            border-radius: 6px;
            margin-top: 1rem;
        }}
        
        .code-block {{
            background: #0d1117;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        
        .recommendations {{
            margin-top: 1rem;
        }}
        
        .recommendations li {{
            margin-left: 1.5rem;
            margin-bottom: 0.5rem;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }}
        
        th {{
            background: var(--accent);
        }}
        
        .meta-info {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 HTTP Smuggling Scan Report</h1>
        <p class="meta-info">
            Target: <strong>{self.metadata.target if self.metadata else 'N/A'}</strong> | 
            Date: <strong>{self.metadata.scan_date if self.metadata else 'N/A'}</strong> |
            Duration: <strong>{self.metadata.scan_duration:.2f}s</strong>
        </p>
        
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value">{len(self.results)}</div>
                <div class="label">Techniques Tested</div>
            </div>
            <div class="summary-item">
                <div class="value {'vulnerable' if vulnerable_count > 0 else 'safe'}">{vulnerable_count}</div>
                <div class="label">Vulnerabilities Found</div>
            </div>
            <div class="summary-item">
                <div class="value">{self.profile.risk_level if self.profile else 'N/A'}</div>
                <div class="label">Risk Level</div>
            </div>
        </div>
'''
        
        # Add server profile section
        if self.profile:
            html += f'''
        <h2>🖥️ Server Profile</h2>
        <div class="card">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Server Header</td><td>{self.profile.server_header or 'Not disclosed'}</td></tr>
                <tr><td>Detected Servers</td><td>{', '.join(s.value for s in self.profile.detected_servers) or 'Unknown'}</td></tr>
                <tr><td>Behind Proxy/CDN</td><td>{'Yes' if self.profile.is_behind_proxy or self.profile.is_behind_cdn else 'No'}</td></tr>
                <tr><td>Supports Chunked</td><td>{'Yes' if self.profile.supports_chunked else 'No'}</td></tr>
                <tr><td>Hints</td><td>{'; '.join(self.profile.hints) or 'None'}</td></tr>
            </table>
        </div>
'''
        
        # Add results section
        html += '''
        <h2>🔍 Detection Results</h2>
'''
        
        for result in self.results:
            status_class = "result-vulnerable" if result.vulnerable else "result-safe"
            badge_color = self._get_severity_color(result.confidence)
            
            html += f'''
        <div class="card result-card {status_class}">
            <div class="result-header">
                <span class="technique-name">{result.technique.value.upper()}</span>
                <span class="badge" style="background: {badge_color}; color: white;">
                    {result.confidence.value.upper()}
                </span>
            </div>
            <p><strong>Status:</strong> {'⚠️ VULNERABLE' if result.vulnerable else '✅ Not Vulnerable'}</p>
            <p><strong>Details:</strong> {result.details}</p>
'''
            
            if result.timing_delay > 0:
                html += f'<p><strong>Timing Delay:</strong> {result.timing_delay:.2f}s</p>'
                
            if result.recommendations:
                html += '''
            <div class="recommendations">
                <strong>Recommendations:</strong>
                <ul>
'''
                for rec in result.recommendations:
                    html += f'                    <li>{rec}</li>\n'
                html += '''                </ul>
            </div>
'''
            
            if result.request_sent:
                html += f'''
            <div class="details">
                <strong>Request Sent:</strong>
                <div class="code-block">{result.request_sent[:500]}</div>
            </div>
'''
            
            html += '        </div>\n'
        
        # Footer
        html += '''
        <h2>📚 References</h2>
        <div class="card">
            <ul>
                <li><a href="https://portswigger.net/research/http-desync-attacks" style="color: #e94560;">HTTP Desync Attacks - PortSwigger Research</a></li>
                <li><a href="https://tools.ietf.org/html/rfc7230" style="color: #e94560;">RFC 7230 - HTTP/1.1 Message Syntax</a></li>
                <li><a href="https://portswigger.net/web-security/request-smuggling" style="color: #e94560;">Web Security Academy - Request Smuggling</a></li>
            </ul>
        </div>
        
        <p class="meta-info" style="text-align: center; margin-top: 2rem;">
            Generated by NetScapeX HTTP Smuggling Detection Tool
        </p>
    </div>
</body>
</html>
'''
        
        return html
    
    def generate_markdown(self, output_path: str) -> str:
        """
        Generate Markdown report.
        
        Args:
            output_path: Path to save Markdown file
            
        Returns:
            Path to generated report
        """
        md = self._build_markdown()
        
        with open(output_path, 'w') as f:
            f.write(md)
            
        return output_path
    
    def _build_markdown(self) -> str:
        """Build Markdown report content"""
        vulnerable_count = sum(1 for r in self.results if r.vulnerable)
        
        md = f'''# HTTP Smuggling Scan Report

**Target:** {self.metadata.target if self.metadata else 'N/A'}  
**Date:** {self.metadata.scan_date if self.metadata else 'N/A'}  
**Duration:** {self.metadata.scan_duration:.2f}s  

## Summary

| Metric | Value |
|--------|-------|
| Techniques Tested | {len(self.results)} |
| Vulnerabilities Found | {vulnerable_count} |
| Risk Level | {self.profile.risk_level if self.profile else 'N/A'} |

---

'''
        
        if self.profile:
            md += f'''## Server Profile

| Property | Value |
|----------|-------|
| Server Header | {self.profile.server_header or 'Not disclosed'} |
| Detected Servers | {', '.join(s.value for s in self.profile.detected_servers) or 'Unknown'} |
| Behind Proxy/CDN | {'Yes' if self.profile.is_behind_proxy or self.profile.is_behind_cdn else 'No'} |
| Supports Chunked | {'Yes' if self.profile.supports_chunked else 'No'} |

---

'''
        
        md += '## Detection Results\n\n'
        
        for result in self.results:
            status = '⚠️ VULNERABLE' if result.vulnerable else '✅ Not Vulnerable'
            
            md += f'''### {result.technique.value.upper()}

**Status:** {status}  
**Confidence:** {result.confidence.value.upper()}  
**Details:** {result.details}

'''
            
            if result.timing_delay > 0:
                md += f'**Timing Delay:** {result.timing_delay:.2f}s\n\n'
                
            if result.recommendations:
                md += '**Recommendations:**\n'
                for rec in result.recommendations:
                    md += f'- {rec}\n'
                md += '\n'
                
            if result.request_sent:
                md += f'''**Request Sent:**
```http
{result.request_sent[:500]}
```

'''
            
            md += '---\n\n'
        
        md += '''## References

- [HTTP Desync Attacks - PortSwigger Research](https://portswigger.net/research/http-desync-attacks)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)
- [Web Security Academy - Request Smuggling](https://portswigger.net/web-security/request-smuggling)
'''
        
        return md
    
    def generate_json(self, output_path: str) -> str:
        """
        Generate JSON report.
        
        Args:
            output_path: Path to save JSON file
            
        Returns:
            Path to generated report
        """
        data = {
            "metadata": {
                "target": self.metadata.target if self.metadata else None,
                "scan_date": self.metadata.scan_date if self.metadata else None,
                "scan_duration": self.metadata.scan_duration if self.metadata else None,
                "techniques_tested": self.metadata.techniques_tested if self.metadata else [],
            },
            "profile": {
                "server_header": self.profile.server_header if self.profile else None,
                "detected_servers": [s.value for s in self.profile.detected_servers] if self.profile else [],
                "is_behind_proxy": self.profile.is_behind_proxy if self.profile else False,
                "is_behind_cdn": self.profile.is_behind_cdn if self.profile else False,
                "risk_level": self.profile.risk_level if self.profile else None,
            } if self.profile else None,
            "results": [r.to_dict() for r in self.results],
            "summary": {
                "total_tests": len(self.results),
                "vulnerabilities_found": sum(1 for r in self.results if r.vulnerable),
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
            
        return output_path
