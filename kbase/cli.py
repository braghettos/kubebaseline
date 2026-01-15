"""Command-line interface for kubebaseline."""

import sys
import logging
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

from kbase.client import KubernetesClient
from kbase.scanner import Scanner
from kbase.report import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def main():
    """kbase - Kubernetes best practices compliance auditing tool."""
    pass


@main.command()
@click.option(
    "--kubeconfig",
    type=click.Path(exists=True),
    help="Path to kubeconfig file (defaults to ~/.kube/config)",
)
@click.option(
    "--context",
    type=str,
    help="Kubernetes context to use",
)
@click.option(
    "--exclude-namespaces",
    type=str,
    help="Comma-separated list of namespaces to exclude from scanning",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (default: stdout)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def report(
    kubeconfig: Optional[str],
    context: Optional[str],
    exclude_namespaces: Optional[str],
    output: Optional[str],
    output_format: str,
    verbose: bool,
):
    """Generate a compliance report for the Kubernetes cluster."""
    
    if verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        # Initialize Kubernetes client
        console.print("🔍 Connecting to Kubernetes cluster...", style="cyan")
        client = KubernetesClient(kubeconfig=kubeconfig, context=context)
        
        cluster_info = client.get_cluster_info()
        console.print(
            f"✅ Connected to cluster (Kubernetes {cluster_info.get('version', 'unknown')})",
            style="green",
        )
        
        # Parse excluded namespaces
        excluded = []
        if exclude_namespaces:
            excluded = [ns.strip() for ns in exclude_namespaces.split(",")]
        
        # Initialize scanner
        scanner = Scanner(client, excluded_namespaces=excluded)
        
        # Run scan
        console.print("\n🔬 Running compliance checks...", style="cyan")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning cluster...", total=None)
            scan_result = scanner.scan()
            progress.update(task, completed=True)
        
        # Generate report
        console.print("\n📊 Generating report...", style="cyan")
        report_generator = ReportGenerator(scan_result, client)
        
        if output_format == "markdown":
            report_content = report_generator.generate()
        else:
            # JSON output (basic implementation)
            import json
            report_data = {
                "scan_date": scan_result.scan_date.isoformat(),
                "scan_duration": scan_result.scan_duration,
                "cluster_info": scan_result.cluster_info,
                "overall_compliance": scan_result.overall_compliance,
                "total_resources": scan_result.total_resources,
                "total_passed": scan_result.total_passed,
                "total_failed": scan_result.total_failed,
                "total_critical": scan_result.total_critical,
                "total_warnings": scan_result.total_warnings,
                "categories": [
                    {
                        "category": cat.category,
                        "compliance": cat.compliance_percentage,
                        "total_resources": cat.total_resources,
                        "total_passed": cat.total_passed,
                        "total_failed": cat.total_failed,
                        "total_critical": cat.total_critical,
                        "total_warnings": cat.total_warnings,
                    }
                    for cat in scan_result.categories
                ],
                "critical_findings": [
                    {
                        "check_id": f.check_id,
                        "check_name": f.check_name,
                        "category": f.category,
                        "severity": f.severity.value,
                        "message": f.message,
                        "resource_type": f.resource_type,
                        "resource_namespace": f.resource_namespace,
                        "resource_name": f.resource_name,
                    }
                    for f in scan_result.get_critical_findings()
                ],
            }
            report_content = json.dumps(report_data, indent=2)
        
        # Output report
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report_content)
            console.print(f"\n✅ Report saved to: {output}", style="green")
        else:
            console.print("\n" + "=" * 80)
            console.print(report_content)
        
        # Print summary
        console.print("\n" + "=" * 80)
        summary_table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Overall Compliance", f"{scan_result.overall_compliance:.1f}%")
        summary_table.add_row("Total Resources", str(scan_result.total_resources))
        summary_table.add_row("Passed", str(scan_result.total_passed))
        summary_table.add_row("Critical Issues", str(scan_result.total_critical))
        summary_table.add_row("Warnings", str(scan_result.total_warnings))
        summary_table.add_row("Scan Duration", f"{scan_result.scan_duration:.2f}s")
        
        console.print(summary_table)
        
        # Exit code based on compliance
        if scan_result.total_critical > 0:
            console.print("\n⚠️  Critical issues found! Please review the report.", style="yellow")
            sys.exit(1)
        elif scan_result.total_warnings > 0:
            console.print("\n⚠️  Warnings found. Consider addressing them.", style="yellow")
            sys.exit(0)
        else:
            console.print("\n✅ All checks passed!", style="green")
            sys.exit(0)
    
    except Exception as e:
        console.print(f"\n❌ Error: {e}", style="red")
        if verbose:
            import traceback
            console.print(traceback.format_exc(), style="red")
        sys.exit(1)


@main.command()
def version():
    """Show version information."""
    console.print("kbase v1.0.0", style="cyan")
    console.print("Kubernetes Best Practices Compliance Auditing Tool", style="dim")


if __name__ == "__main__":
    main()
