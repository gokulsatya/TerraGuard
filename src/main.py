# src/main.py

from parser.file_reader import TerraformFileReader
from rules.base_rules import RulesEngine

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
    
    # Report findings
    if not findings:
        print("No security issues found!")
        return
    
    print(f"\nFound {len(findings)} potential security issues:\n")
    for finding in findings:
        print(f"Issue: {finding['message']}")
        print(f"Severity: {finding['severity']}")
        if finding['line_number']:
            print(f"Line Number: {finding['line_number']}")
        if finding['suggested_fix']:
            print("Suggested Fix:")
            print(finding['suggested_fix'])
        print("-" * 50)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python main.py <terraform_file>")
        sys.exit(1)
    
    analyze_terraform_file(sys.argv[1])