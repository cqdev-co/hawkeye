import os
import subprocess
import sys
from pathlib import Path

def create_virtualenv(venv_path: Path):
    """Create a virtual environment."""
    print(f"Creating virtual environment at {venv_path}...")
    subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], check=True)
    print("Virtual environment created.")

    # Verify pip installation
    pip_executable = venv_path / 'Scripts' / 'pip' if os.name == 'nt' else venv_path / 'bin' / 'pip'
    if not pip_executable.exists():
        print("pip not found, attempting to install pip...")
        subprocess.run([str(venv_path / 'Scripts' / 'python'), '-m', 'ensurepip'], check=True)

    # Upgrade pip
    print("Upgrading pip to the latest version...")
    subprocess.run([str(venv_path / 'Scripts' / 'python'), '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
    print("pip upgraded.")

def install_requirements(venv_path: Path, requirements_file: Path):
    """Install packages from requirements.txt."""
    pip_executable = venv_path / 'Scripts' / 'pip' if os.name == 'nt' else venv_path / 'bin' / 'pip'

    print(f"Installing packages from {requirements_file}...")
    subprocess.run([str(pip_executable), 'install', '-r', str(requirements_file)], check=True)
    print("Packages installed.")

def main():
    # Define paths
    scripts_dir = Path(__file__).parent.resolve()  # This is the scripts directory
    venv_path = scripts_dir.parent / 'venv'  # Create venv in the project root
    requirements_file = scripts_dir / 'requirements.txt'  # requirements.txt in scripts directory

    # Check if requirements.txt exists
    if not requirements_file.exists():
        print(f"Error: {requirements_file} does not exist.")
        sys.exit(1)

    # Create virtual environment if it doesn't exist
    if not venv_path.exists():
        create_virtualenv(venv_path)
    else:
        print(f"Virtual environment already exists at {venv_path}.")

    # Install requirements
    install_requirements(venv_path, requirements_file)

if __name__ == '__main__':
    main()
