# src/main.py

from parser.file_reader import TerraformFileReader
from rules.base_rules import RulesEngine
from report.generator import ReportGenerator

def analyze_terraform_file(filepath: str) -> None:
    """
    Analyzes a Terraform file for security issues
    """
    # Initialize our components
    reader = TerraformFileReader()
    engine = RulesEngine()
    
    # Try to read the file
    if not reader.read_file(filepath):
        print("Failed to read file!")
        for error in reader.get_errors():
            print(f"Error: {error}")
        return
    
    # Verify it's a Terraform file
    if not reader.is_terraform_file():
        print(f"Warning: {filepath} doesn't appear to be a Terraform configuration file")
        return
    
    # Analyze the content
    content = reader.get_content()
    findings = engine.analyze(content)
    
    # Generate a colored report
    ReportGenerator.generate_report(findings)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python main.py <terraform_file>")
        sys.exit(1)
    
    analyze_terraform_file(sys.argv[1])