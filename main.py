#!/usr/bin/env python3
"""
NetScapeX - HTTP Request Smuggling Detection Tool

A comprehensive tool for detecting and exploiting HTTP request smuggling vulnerabilities.

Usage:
    python main.py scan --target https://example.com
    python main.py scan --target https://example.com --techniques cl-te,te-cl
    python main.py profile --target https://example.com
    python main.py exploit --target https://example.com --type cache-poison
"""

import click
import time
import sys
from typing import List, Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from config import TechniqueType, ScanConfig
from scanner.profiler import TargetProfiler
from scanner.detector import SmuggleDetector, Confidence
from payloads.generator import PayloadGenerator
from reports.generator import ReportGenerator

console = Console()




@click.group()
@click.option('--quiet', '-q', is_flag=True, help='Suppress banner output')
def cli(quiet: bool):

@cli.command()
@click.option('--target', '-t', required=True, help='Target URL (e.g., https://example.com)')
@click.option('--techniques', '-T', default='cl-te,te-cl,te-te', 
              help='Comma-separated techniques to test (cl-te, te-cl, te-te)')
@click.option('--timeout', default=10.0, help='Request timeout in seconds')
@click.option('--report', '-r', default=None, help='Output report path (.html, .md, or .json)')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL certificate verification')
def scan(target: str, techniques: str, timeout: float, report: Optional[str], 
         verbose: bool, no_ssl_verify: bool):
    """Scan target for HTTP smuggling vulnerabilities"""
    
    console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Techniques:[/bold cyan] {techniques}")
    console.print(f"[bold cyan]Timeout:[/bold cyan] {timeout}s\n")
    
    # Parse techniques
    technique_map = {
        'cl-te': TechniqueType.CL_TE,
        'te-cl': TechniqueType.TE_CL,
        'te-te': TechniqueType.TE_TE,
    }
    
    selected_techniques = []
    for t in techniques.split(','):
        t = t.strip().lower()
        if t in technique_map:
            selected_techniques.append(technique_map[t])
        else:
            console.print(f"[yellow]Warning: Unknown technique '{t}'[/yellow]")
    
    if not selected_techniques:
        console.print("[red]Error: No valid techniques specified[/red]")
        sys.exit(1)
    
    start_time = time.time()
    
    # Profile target first
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Profiling target...", total=None)
        
        try:
            profiler = TargetProfiler(timeout=timeout, verify_ssl=not no_ssl_verify)
            profile = profiler.profile(target)
            progress.update(task, description="[green]Profiling complete!")
        except Exception as e:
            progress.update(task, description=f"[red]Profiling failed: {e}")
            profile = None
    
    # Display profile info
    if profile:
        console.print("\n[bold]Server Profile:[/bold]")
        table = Table(show_header=False, box=None)
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        
        table.add_row("Server", profile.server_header or "Not disclosed")
        table.add_row("Detected", ", ".join(s.value for s in profile.detected_servers) or "Unknown")
        table.add_row("Behind Proxy/CDN", "Yes" if profile.is_behind_proxy or profile.is_behind_cdn else "No")
        table.add_row("Risk Level", profile.risk_level)
        
        console.print(table)
        console.print()
    
    # Run detection
    detector = SmuggleDetector(
        target,
        timeout=timeout,
        verify_ssl=not no_ssl_verify
    )
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        for technique in selected_techniques:
            task = progress.add_task(f"Testing {technique.value}...", total=None)
            
            try:
                result = detector.detect(technique)
                results.append(result)
                
                if result.vulnerable:
                    progress.update(task, description=f"[red]⚠️ {technique.value}: VULNERABLE ({result.confidence.value})")
                else:
                    progress.update(task, description=f"[green]✓ {technique.value}: Not vulnerable")
                    
            except Exception as e:
                progress.update(task, description=f"[yellow]! {technique.value}: Error - {e}")
                
            time.sleep(0.5)  # Brief pause between tests
    
    scan_duration = time.time() - start_time
    
    # Display results summary
    console.print("\n" + "="*60)
    console.print("[bold]SCAN RESULTS[/bold]")
    console.print("="*60 + "\n")
    
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    
    results_table = Table(title="Detection Results")
    results_table.add_column("Technique", style="cyan")
    results_table.add_column("Status")
    results_table.add_column("Confidence")
    results_table.add_column("Details")
    
    for result in results:
        status = "[red]VULNERABLE[/red]" if result.vulnerable else "[green]Safe[/green]"
        
        confidence_colors = {
            Confidence.CONFIRMED: "red",
            Confidence.PROBABLE: "yellow",
            Confidence.POSSIBLE: "yellow",
            Confidence.UNLIKELY: "green",
            Confidence.ERROR: "dim",
        }
        conf_color = confidence_colors.get(result.confidence, "white")
        
        results_table.add_row(
            result.technique.value.upper(),
            status,
            f"[{conf_color}]{result.confidence.value}[/{conf_color}]",
            result.details[:50] + "..." if len(result.details) > 50 else result.details
        )
    
    console.print(results_table)
    
    # Summary panel
    if vulnerable_count > 0:
        summary = Panel(
            f"[red bold]⚠️ Found {vulnerable_count} potential vulnerability(ies)![/red bold]\n\n"
            f"Scan completed in {scan_duration:.2f}s",
            title="Summary",
            border_style="red"
        )
    else:
        summary = Panel(
            f"[green bold]✓ No vulnerabilities detected[/green bold]\n\n"
            f"Scan completed in {scan_duration:.2f}s",
            title="Summary",
            border_style="green"
        )
    
    console.print("\n")
    console.print(summary)
    
    # Generate report if requested
    if report:
        console.print(f"\n[cyan]Generating report: {report}[/cyan]")
        
        report_gen = ReportGenerator()
        report_gen.set_metadata(
            target=target,
            scan_duration=scan_duration,
            techniques=[t.value for t in selected_techniques]
        )
        
        if profile:
            report_gen.add_profile(profile)
        report_gen.add_results(results)
        
        # Determine format from extension
        report_path = Path(report)
        if report_path.suffix == '.html':
            report_gen.generate_html(report)
        elif report_path.suffix == '.md':
            report_gen.generate_markdown(report)
        elif report_path.suffix == '.json':
            report_gen.generate_json(report)
        else:
            # Default to HTML
            report_gen.generate_html(report)
            
        console.print(f"[green]Report saved to: {report}[/green]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--timeout', default=10.0, help='Request timeout')
@click.option('--no-ssl-verify', is_flag=True, help='Disable SSL verification')
def profile(target: str, timeout: float, no_ssl_verify: bool):
    """Profile a target server"""
    
    console.print(f"\n[bold cyan]Profiling:[/bold cyan] {target}\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing target...", total=None)
        
        profiler = TargetProfiler(timeout=timeout, verify_ssl=not no_ssl_verify)
        result = profiler.profile(target)
        
        progress.update(task, description="[green]Analysis complete!")
    
    # Display results
    console.print("\n[bold]Server Profile[/bold]")
    console.print("="*50)
    
    table = Table(show_header=False)
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value")
    
    table.add_row("Hostname", result.hostname)
    table.add_row("Port", str(result.port))
    table.add_row("SSL/TLS", "Yes" if result.uses_ssl else "No")
    table.add_row("Server Header", result.server_header or "Not disclosed")
    table.add_row("Detected Servers", ", ".join(s.value for s in result.detected_servers) or "Unknown")
    table.add_row("Behind Proxy", "Yes" if result.is_behind_proxy else "No")
    table.add_row("Behind CDN", "Yes" if result.is_behind_cdn else "No")
    table.add_row("Supports Chunked", "Yes" if result.supports_chunked else "No")
    table.add_row("Keep-Alive", "Yes" if result.supports_keep_alive else "No")
    table.add_row("Risk Level", f"[{'red' if result.risk_level == 'HIGH' else 'yellow' if result.risk_level == 'MEDIUM' else 'green'}]{result.risk_level}[/]")
    
    console.print(table)
    
    if result.hints:
        console.print("\n[bold]Hints:[/bold]")
        for hint in result.hints:
            console.print(f"  • {hint}")


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--technique', '-T', default='cl-te', 
              type=click.Choice(['cl-te', 'te-cl']), 
              help='Smuggling technique')
@click.option('--type', 'exploit_type', default='hijack',
              type=click.Choice(['hijack', 'cache-poison']),
              help='Exploit type')
@click.option('--path', '-p', default='/', help='Target path')
@click.option('--timeout', default=30.0, help='Request timeout')
def exploit(target: str, technique: str, exploit_type: str, path: str, timeout: float):
    """Attempt exploitation (use responsibly!)"""
    
    console.print(Panel(
        "[yellow bold]⚠️ WARNING: Only use this against systems you have permission to test![/yellow bold]",
        border_style="yellow"
    ))
    
    console.print(f"\n[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Technique:[/bold cyan] {technique}")
    console.print(f"[bold cyan]Exploit Type:[/bold cyan] {exploit_type}\n")
    
    if exploit_type == 'hijack':
        from exploits.request_hijack import RequestHijacker
        
        hijacker = RequestHijacker(target, timeout=timeout)
        
        with console.status("Attempting request hijack..."):
            result = hijacker.hijack(path, technique=technique)
        
        if result.success:
            console.print("[red bold]✓ Request hijack may be possible![/red bold]")
            console.print(f"Details: {result.details}")
            if result.captured_request:
                console.print("\nCaptured data:")
                console.print(Panel(result.captured_request[:500]))
        else:
            console.print("[yellow]Request hijack unsuccessful[/yellow]")
            console.print(f"Details: {result.details}")
            
    elif exploit_type == 'cache-poison':
        from exploits.cache_poison import CachePoisoner
        
        poisoner = CachePoisoner(target, technique=technique, timeout=timeout)
        
        console.print("Checking cache status...")
        cache_info = poisoner.check_cacheability(path)
        
        if cache_info['cacheable']:
            console.print(f"[yellow]Path appears cacheable: {cache_info}[/yellow]")
            
            with console.status("Attempting cache poisoning..."):
                result = poisoner.poison(path)
            
            if result.success:
                console.print("[red bold]✓ Cache poisoning may have succeeded![/red bold]")
            else:
                console.print("[yellow]Cache poisoning unsuccessful[/yellow]")
            console.print(f"Details: {result.details}")
        else:
            console.print("[green]Path does not appear to be cached[/green]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target hostname')
@click.option('--technique', '-T', default='cl-te', help='Technique to generate payloads for')
@click.option('--path', '-p', default='/', help='Target path')
def payloads(target: str, technique: str, path: str):
    """Generate smuggling payloads"""
    
    console.print(f"\n[bold cyan]Generating {technique} payloads for {target}[/bold cyan]\n")
    
    gen = PayloadGenerator(target)
    
    if technique == 'cl-te':
        payload_list = [
            ("Timing Probe", gen.cl_te_timing_probe(path)),
            ("Basic Probe", gen.cl_te_basic_probe(path)),
            ("Prefix Smuggle", gen.cl_te_smuggle_prefix(path)),
        ]
    elif technique == 'te-cl':
        payload_list = [
            ("Timing Probe", gen.te_cl_timing_probe(path)),
            ("Request Smuggle", gen.te_cl_smuggle_request(path)),
        ]
    else:
        payload_list = [
            (f"TE Variant {i+1}", p) for i, p in enumerate(gen.te_te_variants(path)[:5])
        ]
    
    for name, payload in payload_list:
        console.print(Panel(
            payload,
            title=f"[bold]{name}[/bold]",
            border_style="cyan"
        ))
        console.print()


if __name__ == "__main__":
    cli()
