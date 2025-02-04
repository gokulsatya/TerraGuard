# src/main.py

# Add imports at the top
from rules.cloudwatch_rules import CloudWatchLogRetentionRule, CloudWatchLogEncryptionRule
from rules.cloud_service_rules import ElasticSearchSecurityRule, LambdaSecurityRule
from rules.database_rules import RDSEncryptionRule, RDSPublicAccessRule, RDSBackupRule
from parser.file_reader import TerraformFileReader
from rules.base_rules import RulesEngine
from rules.api_gateway_rules import APIGatewayAuthorizationRule
from rules.network_rules import SecurityGroupRule, PortExposureRule, NetworkACLRule
from rules.s3_rules import (
    S3PublicAccessRule,
    S3EncryptionRule,
    S3LoggingRule,
    S3VersioningRule
)
from rules.iam_rules import (
    IAMAdminPolicyRule, 
    IAMUserCredentialsRule, 
    IAMRolePermissionsRule,
    IAMPasswordPolicyRule         # New
)
from rules.container_db_rules import (
    ECSSecurityRule,
    EKSSecurityRule,
    DynamoDBSecurityRule
)
from report.generator import ReportGenerator

def analyze_terraform_file(filepath: str) -> None:
    """
    Analyzes a Terraform file for security issues and generates comprehensive reports
    """
    # Initialize our components
    reader = TerraformFileReader()
    engine = RulesEngine()
    
    # Register all our rules
    engine.register_rule(S3PublicAccessRule())
    engine.register_rule(S3EncryptionRule())
    engine.register_rule(SecurityGroupRule())
    engine.register_rule(IAMAdminPolicyRule())
    engine.register_rule(IAMUserCredentialsRule())
    engine.register_rule(IAMRolePermissionsRule())
    engine.register_rule(IAMPasswordPolicyRule())      # New
    engine.register_rule(CloudWatchLogRetentionRule())
    engine.register_rule(CloudWatchLogEncryptionRule())
    engine.register_rule(APIGatewayAuthorizationRule())
    engine.register_rule(RDSEncryptionRule())
    engine.register_rule(RDSPublicAccessRule())
    engine.register_rule(RDSBackupRule())
    engine.register_rule(PortExposureRule())
    engine.register_rule(NetworkACLRule())
    engine.register_rule(ElasticSearchSecurityRule())
    engine.register_rule(LambdaSecurityRule())
    engine.register_rule(ECSSecurityRule())
    engine.register_rule(EKSSecurityRule())
    engine.register_rule(DynamoDBSecurityRule())

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
    
    # Generate both console and HTML reports
    ReportGenerator.generate_report(findings, filepath)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python main.py <terraform_file>")
        sys.exit(1)
    
    analyze_terraform_file(sys.argv[1])