# reporter.py
from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from datetime import datetime
import json

class ScanReporter:
    def __init__(self):
        self.console = Console()
        self.start_time = datetime.now()

    def print_header(self):
        """Print the scanner header"""
        self.console.print(Panel(
            Text("HawkEye Dependency Scanner", style="bold white", justify="center"),
            subtitle="Scanning repositories for vulnerabilities",
            style="blue",
        ))

    def create_progress_bar(self) -> Progress:
        """Create and return a progress bar for repository scanning"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            "[bold]{task.fields[status]}",
            console=self.console
        )

    def print_repo_summary(self, results: List[Dict]):
        """Print a summary of scanned repositories"""
        total_repos = len(results)
        successful_scans = len([r for r in results if 'error' not in r])
        failed_scans = total_repos - successful_scans

        summary_table = Table(show_header=False, box=None)
        summary_table.add_row("Total Repositories Scanned:", f"[bold]{total_repos}[/]")
        summary_table.add_row("Successful Scans:", f"[green]{successful_scans}[/]")
        summary_table.add_row("Failed Scans:", f"[red]{failed_scans}[/]")

        self.console.print("\n[bold]Scan Summary[/]")
        self.console.print(Panel(summary_table))

    def print_vulnerability_report(self, results: List[Dict]):
        """Print detailed vulnerability report"""
        vuln_tree = Tree("[bold]Vulnerability Report[/]")

        total_vulnerabilities = 0
        repos_with_vulns = 0

        for result in results:
            if 'error' in result:
                continue

            repo_vulns = result.get('vulnerabilities', [])
            if repo_vulns:
                repos_with_vulns += 1
                total_vulnerabilities += len(repo_vulns)
                repo_branch = vuln_tree.add(
                    f"[yellow]{result['repo_name']}[/] ([red]{len(repo_vulns)} vulnerabilities[/])"
                )

                for vuln in repo_vulns:
                    vuln_text = f"[red]{vuln['dependency']}[/] ({vuln['type']})"
                    repo_branch.add(vuln_text)

        if total_vulnerabilities > 0:
            self.console.print("\n[bold red]⚠️  Vulnerabilities Found[/]")
            self.console.print(Panel(vuln_tree))
        else:
            self.console.print("\n[bold green]✓ No vulnerabilities found[/]")

    def print_dependency_summary(self, results: List[Dict]):
        """Print summary of dependencies found"""
        dep_table = Table(
            "Repository", "NPM", "Yarn", "Python",
            title="Dependencies by Repository",
            style="blue"
        )

        for result in results:
            if 'error' in result:
                continue

            deps = result['dependencies']
            dep_table.add_row(
                result['repo_name'],
                str(len(deps['npm'])),
                str(len(deps['yarn'])),
                str(len(deps['python']))
            )

        self.console.print("\n")
        self.console.print(dep_table)

    def print_scan_time(self):
        """Print the total scan time"""
        duration = datetime.now() - self.start_time
        self.console.print(f"\n[bold]Total Scan Time:[/] {duration.total_seconds():.2f} seconds")

    def save_detailed_report(self, results: List[Dict], output_file: str):
        """Save detailed JSON report"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.console.print(f"\n[bold green]Detailed report saved to:[/] {output_file}")

    def print_final_summary(self, results: List[Dict]):
        """Print the final summary of the scan"""
        self.console.rule("[bold]Scan Complete")
        self.print_repo_summary(results)
        self.print_dependency_summary(results)
        self.print_vulnerability_report(results)
        self.print_scan_time()
