#!/usr/bin/env python3
# Dependency checking utilities

import sys
import importlib
from typing import Dict, List, Tuple

def check_dependencies(skip_checks: bool = False) -> bool:
    """
    Check if all required dependencies are installed.
    
    Args:
        skip_checks: Whether to skip dependency checks
        
    Returns:
        True if all dependencies are available or checks are skipped, False otherwise
    """
    if skip_checks:
        print("✅ Skipping dependency checks as requested.")
        return True
        
    # Dictionary of required modules and their pip install commands
    required_modules = {
        # Core analysis modules
        'sklearn': 'scikit-learn',
        'joblib': 'joblib',
        
        # Code analysis modules
        'astroid': 'astroid',
        'radon': 'radon',
        
        # Binary analysis modules
        'pefile': 'pefile',
        'elftools': 'pyelftools',
        'macholib': 'macholib',
        'magic': 'python-magic',  # File type detection
        
        # Optional but recommended modules
        'colorama': 'colorama',   # For colored terminal output
        'tqdm': 'tqdm',           # For progress bars
    }
    
    # NLP module (optional but with additional steps)
    nlp_modules = {
        'spacy': 'spacy'
    }
    
    # Check each module
    missing_modules = []
    
    for module_name, pip_package in required_modules.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing_modules.append((module_name, pip_package))
    
    # If any modules are missing, show error
    if missing_modules:
        print("\n❌ ERROR: Missing required dependencies")
        print("=" * 50)
        print("The following dependencies are required but not installed:")
        
        for module_name, pip_package in missing_modules:
            print(f"  - {module_name} (install with: pip install {pip_package})")
        
        print("\nTo install all dependencies at once, run:")
        pip_command = "pip install " + " ".join(pkg for _, pkg in missing_modules)
        print(f"  {pip_command}")
        
        # Check NLP modules separately
        for module_name, pip_package in nlp_modules.items():
            try:
                importlib.import_module(module_name)
                # If spaCy is installed, check for language model
                if module_name == 'spacy':
                    import spacy
                    try:
                        spacy.load("en_core_web_sm")
                    except OSError:
                        print("\nAdditional note for spaCy:")
                        print("  After installing spaCy, you also need to download the language model:")
                        print("  python -m spacy download en_core_web_sm")
            except ImportError:
                print("\nOptional NLP module:")
                print(f"  - {module_name} (install with: pip install {pip_package})")
                print("  After installing spaCy, download the language model with:")
                print("  python -m spacy download en_core_web_sm")
        
        print("\nExiting due to missing dependencies.")
        return False
    
    # Check if spaCy language model is installed
    if 'spacy' not in dict(missing_modules):
        try:
            import spacy
            try:
                spacy.load("en_core_web_sm")
            except OSError:
                print("\n⚠️ WARNING: Missing spaCy language model")
                print("=" * 50)
                print("The spaCy module is installed, but the language model is missing.")
                print("Install it with: python -m spacy download en_core_web_sm")
                print("Semantic analysis features will be disabled.")
        except ImportError:
            # spaCy is optional, so just note it
            print("\n⚠️ Note: spaCy is not installed. Semantic analysis features will be disabled.")
    
    # If we get here, all dependencies are installed
    print("✅ All required dependencies are installed correctly.\n")
    return True

def generate_requirements_file(output_path: str = "requirements.txt") -> None:
    """
    Generate a requirements.txt file with all needed dependencies.
    
    Args:
        output_path: Path where the requirements file should be saved
    """
    requirements = [
        "scikit-learn>=1.0.0",
        "joblib>=1.1.0",
        "spacy>=3.4.0",
        "astroid>=2.11.0",
        "radon>=5.1.0",
        "pefile>=2023.2.7",
        "pyelftools>=0.29",
        "macholib>=1.16",
        "python-magic>=0.4.27",
        "colorama>=0.4.6",
        "tqdm>=4.65.0"
    ]
    
    with open(output_path, "w") as f:
        f.write("# Requirements for file-analyzer\n")
        f.write("# Install with: pip install -r requirements.txt\n\n")
        for req in requirements:
            f.write(f"{req}\n")
        
        # Add note about spaCy model
        f.write("\n# After installing dependencies, run:\n")
        f.write("# python -m spacy download en_core_web_sm\n")
    
    print(f"✅ Generated requirements file at {output_path}")
    print("Install all dependencies with: pip install -r requirements.txt")
    print("Don't forget to also run: python -m spacy download en_core_web_sm")

def setup_colored_output():
    """
    Set up colored terminal output for better readability.
    
    Returns:
        Dict of color functions or no-op functions if colorama is not available
    """
    try:
        from colorama import init, Fore, Style
        init()  # Initialize colorama
        
        # Define color functions
        def red(text): return f"{Fore.RED}{text}{Style.RESET_ALL}"
        def green(text): return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
        def yellow(text): return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
        def blue(text): return f"{Fore.BLUE}{text}{Style.RESET_ALL}"
        def magenta(text): return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
        def cyan(text): return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
        
        return {
            "red": red,
            "green": green,
            "yellow": yellow,
            "blue": blue, 
            "magenta": magenta,
            "cyan": cyan
        }
    except ImportError:
        # Fallback if colorama is not available
        def no_color(text): return text
        return {
            "red": no_color,
            "green": no_color,
            "yellow": no_color,
            "blue": no_color,
            "magenta": no_color,
            "cyan": no_color
        } 