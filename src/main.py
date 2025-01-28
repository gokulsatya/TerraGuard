# src/main.py

from parser.file_reader import TerraformFileReader
from rules.base_rules import RulesEngine
from rules.network_rules import SecurityGroupRule
from report.generator import ReportGenerator
from rules.s3_rules import S3PublicAccessRule, S3EncryptionRule  # We'll create this in a moment

def analyze_terraform_file(filepath: str) -> None:
    """
    Analyzes a Terraform file for security issues
    """
    # Initialize our components
    reader = TerraformFileReader()
    engine = RulesEngine()
    
    # Register all our rules
    engine.register_rule(S3PublicAccessRule())
    engine.register_rule(S3EncryptionRule())
    engine.register_rule(SecurityGroupRule())
    
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