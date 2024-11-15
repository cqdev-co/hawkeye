import os
import shutil
from pathlib import Path
import git
from dotenv import load_dotenv
import json
import yaml
from typing import List, Dict
import requests
import tempfile
from reporter import ScanReporter

# Load environment variables
load_dotenv()
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
EXCLUDED_REPOS = os.getenv('EXCLUDED_REPOS', '').split(',')
ORGANIZATION = os.getenv('ORGANIZATION')

class DependencyScanner:
    def __init__(self, repo_url: str, repo_name: str):
        self.repo_url = repo_url
        self.repo_name = repo_name
        self.repo_path = None
        self.package_managers = {}  # Store package manager per directory
        self.dependencies = {
            'npm': [],
            'yarn': [],
            'python': []
        }

    def detect_package_manager(self, directory: Path) -> str:
        """Detect which package manager is being used in a specific directory"""
        try:
            if not directory.exists():
                return None

            yarn_lock = directory / 'yarn.lock'
            package_lock = directory / 'package-lock.json'
            package_json = directory / 'package.json'

            if yarn_lock.exists():
                print(f"Found yarn.lock in {directory}")
                return 'yarn'
            elif package_lock.exists():
                print(f"Found package-lock.json in {directory}")
                return 'npm'
            elif package_json.exists():
                print(f"Found package.json in {directory}")
                try:
                    with open(package_json) as f:
                        package_data = json.load(f)
                        if 'packageManager' in package_data and 'yarn' in package_data['packageManager'].lower():
                            return 'yarn'
                except Exception as e:
                    print(f"Error reading package.json in {directory}: {e}")
                return 'npm'
            return None
        except Exception as e:
            print(f"Error detecting package manager in {directory}: {e}")
            return None
    
    def parse_dependencies(self, file_info: Dict) -> None:
        try:
            file_path = Path(file_info['path'])
            file_type = file_info['type']
            directory = file_path.parent

            print(f"Parsing dependencies from {file_path}")

            if file_type in ['npm', 'yarn']:
                # Detect package manager for this directory if not already detected
                if directory not in self.package_managers:
                    self.package_managers[directory] = self.detect_package_manager(directory)
                
                package_manager = self.package_managers[directory]
                if not package_manager:
                    print(f"No package manager detected for {directory}")
                    return

                if file_path.name == 'package.json':
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if not content.strip():
                                print(f"Empty package.json file in {directory}")
                                return
                            
                            package_data = json.loads(content)
                            if not isinstance(package_data, dict):
                                print(f"Invalid package.json format in {directory}")
                                return

                            dependencies = {
                                **package_data.get('dependencies', {}),
                                **package_data.get('devDependencies', {})
                            }

                            if dependencies:
                                self.dependencies[package_manager].extend([
                                    {'name': name, 'version': version}
                                    for name, version in dependencies.items()
                                ])
                                print(f"Successfully parsed {len(dependencies)} dependencies from package.json in {directory}")
                            else:
                                print(f"No dependencies found in package.json for {directory}")

                    except json.JSONDecodeError as e:
                        print(f"JSON parsing error in package.json for {directory}: {e}")
                    except Exception as e:
                        print(f"Unexpected error parsing package.json for {directory}: {e}")

                elif file_path.name == 'yarn.lock':
                    package_manager = self.package_managers.get(directory)
                    if package_manager == 'yarn':
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                dependencies = []
                                current_package = None
                                
                                for line in content.split('\n'):
                                    line = line.strip()
                                    if line.startswith('"'):
                                        package_line = line.strip('"')
                                        if '@' in package_line:
                                            parts = package_line.split('@')
                                            if parts[0].startswith('@'):
                                                # Scoped package
                                                current_package = '@' + parts[1].split(',')[0]
                                            else:
                                                current_package = parts[0]
                                            
                                            if current_package and current_package not in dependencies:
                                                dependencies.append(current_package)

                                self.dependencies['yarn'].extend([
                                    {'name': dep, 'version': 'unknown'}
                                    for dep in dependencies
                                ])
                                print(f"Successfully parsed {len(dependencies)} dependencies from yarn.lock")

                        except Exception as e:
                            print(f"Error parsing yarn.lock for {self.repo_name}: {e}")

            elif file_type == 'python':
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        requirements = [
                            line.strip()
                            for line in f.readlines()
                            if line.strip() and not line.startswith('#')
                        ]
                        self.dependencies['python'].extend([
                            {'name': req, 'version': 'unknown'}
                            for req in requirements
                        ])
                        print(f"Successfully parsed {len(requirements)} dependencies from requirements.txt")

                except Exception as e:
                    print(f"Error parsing requirements.txt for {self.repo_name}: {e}")

        except Exception as e:
            print(f"Error in parse_dependencies for {self.repo_name}: {e}")

    def check_vulnerabilities(self):
        """Check for vulnerabilities in dependencies"""
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v4+json'
        }

        vulnerabilities = []
        
        for dep_type, deps in self.dependencies.items():
            if not deps:  # Skip empty dependency lists
                continue
                
            for dep in deps:
                dep_name = dep['name']
                
                response = requests.get(
                    f'https://api.github.com/advisories',
                    headers=headers,
                    params={'package': dep_name}
                )
                
                if response.status_code == 200:
                    vulns = response.json()
                    if vulns:
                        # Use the actual dependency type instead of trying to access package_manager
                        vulnerabilities.append({
                            'dependency': dep_name,
                            'type': dep_type,
                            'version': dep.get('version', 'unknown'),
                            'vulnerabilities': vulns
                        })

        return vulnerabilities
    
    def clone_repository(self, target_dir: str) -> None:
        """Clone the repository to analyze"""
        try:
            self.repo_path = Path(target_dir)
            git.Repo.clone_from(self.repo_url, target_dir)
            print(f"Successfully cloned {self.repo_name}")
        except git.GitCommandError as e:
            print(f"Error cloning repository {self.repo_name}: {e}")
            raise

    def find_dependency_files(self) -> List[Dict]:
        """Find all dependency files in the repository"""
        dependency_files = []
        
        for path in self.repo_path.rglob('*'):
            if path.is_file():
                if path.name in ['package.json', 'yarn.lock', 'requirements.txt']:
                    dependency_files.append({
                        'path': str(path),
                        'type': self._get_file_type(path.name),
                        'directory': str(path.parent)
                    })
        
        return dependency_files

    def _get_file_type(self, filename: str) -> str:
        """Determine the type of dependency file"""
        if filename == 'package.json':
            return 'npm'
        elif filename == 'yarn.lock':
            return 'yarn'
        elif filename == 'requirements.txt':
            return 'python'
        
def get_organization_repos(org_name: str, token: str) -> List[Dict]:
    """Fetch all repositories from the organization"""
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    repos = []
    page = 1
    while True:
        response = requests.get(
            f'https://api.github.com/orgs/{org_name}/repos',
            headers=headers,
            params={'page': page, 'per_page': 100}
        )
        
        if response.status_code != 200:
            print(f"Error fetching repositories: {response.status_code}")
            break
            
        page_repos = response.json()
        if not page_repos:
            break
            
        repos.extend(page_repos)
        page += 1
    
    return repos

def scan_repository(repo_url: str, repo_name: str) -> Dict:
    """Scan a single repository and return results"""
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            scanner = DependencyScanner(repo_url, repo_name)
            scanner.clone_repository(temp_dir)
            
            dependency_files = scanner.find_dependency_files()
            for file_info in dependency_files:
                scanner.parse_dependencies(file_info)
            
            vulnerabilities = scanner.check_vulnerabilities()
            
            return {
                'repo_name': repo_name,
                'dependencies': scanner.dependencies,
                'vulnerabilities': vulnerabilities
            }
        except Exception as e:
            print(f"Error scanning repository {repo_name}: {e}")
            return {
                'repo_name': repo_name,
                'error': str(e)
            }

def main():
    if not all([GITHUB_TOKEN, ORGANIZATION]):
        print("Error: GitHub token and organization name are required.")
        return

    reporter = ScanReporter()
    reporter.print_header()

    # Fetch all repositories from the organization
    reporter.console.print(f"\nFetching repositories from [bold]{ORGANIZATION}[/]...")
    repos = get_organization_repos(ORGANIZATION, GITHUB_TOKEN)
    
    if not repos:
        reporter.console.print("[red]No repositories found or error fetching repositories.[/]")
        return

    results = []
    with reporter.create_progress_bar() as progress:
        scan_task = progress.add_task(
            "Scanning repositories...", 
            total=len(repos), 
            status="Starting"
        )

        for repo in repos:
            if repo['name'] in EXCLUDED_REPOS:
                progress.update(scan_task, advance=1, status=f"Skipped {repo['name']}")
                continue

            progress.update(scan_task, status=f"Scanning {repo['name']}")
            result = scan_repository(repo['clone_url'], repo['name'])
            results.append(result)
            progress.update(scan_task, advance=1)

    # Save and display results
    reporter.save_detailed_report(results, 'scan_results.json')
    reporter.print_final_summary(results)

if __name__ == "__main__":
    main()
