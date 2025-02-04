# src/rules/cloud_service_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class ElasticSearchSecurityRule(SecurityRule):
    """
    Checks for security configurations in Elasticsearch domains.
    Elasticsearch can expose sensitive data if not properly secured.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "ElasticSearchSecurity"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_elasticsearch_domain"' in content:
            domain_blocks = re.finditer(
                r'resource\s+"aws_elasticsearch_domain"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for domain in domain_blocks:
                domain_name = domain.group(1)
                domain_config = domain.group(2)
                
                # Check for encryption at rest
                if not re.search(r'encrypt_at_rest\s*{[^}]*enabled\s*=\s*true', domain_config):
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"Elasticsearch domain '{domain_name}' does not have encryption at rest enabled",
                        None
                    )
                    finding.add_suggestion("""
                        Enable encryption at rest:
                        resource "aws_elasticsearch_domain" "example" {
                          # ... other configuration ...
                          encrypt_at_rest {
                            enabled = true
                          }
                        }""")
                    self.findings.append(finding)
                
                # Check for node-to-node encryption
                if not re.search(r'node_to_node_encryption\s*{[^}]*enabled\s*=\s*true', domain_config):
                    finding = SecurityFinding(
                        "ElasticSearchNodeEncryption",
                        self.severity,
                        f"Elasticsearch domain '{domain_name}' does not have node-to-node encryption enabled",
                        None
                    )
                    finding.add_suggestion("""
                        Enable node-to-node encryption:
                        resource "aws_elasticsearch_domain" "example" {
                          # ... other configuration ...
                          node_to_node_encryption {
                            enabled = true
                          }
                        }""")
                    self.findings.append(finding)
        
        return self.findings

class LambdaSecurityRule(SecurityRule):
    """
    Checks for security best practices in Lambda functions.
    Lambda functions need proper IAM roles and encryption settings.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "LambdaSecurity"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_lambda_function"' in content:
            lambda_blocks = re.finditer(
                r'resource\s+"aws_lambda_function"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for lambda_func in lambda_blocks:
                func_name = lambda_func.group(1)
                func_config = lambda_func.group(2)
                
                # Check for environment variable encryption
                if 'environment' in func_config and not re.search(r'kms_key_arn', func_config):
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"Lambda function '{func_name}' has unencrypted environment variables",
                        None
                    )
                    finding.add_suggestion("""
                        Encrypt environment variables with KMS:
                        resource "aws_lambda_function" "example" {
                          # ... other configuration ...
                          environment {
                            variables = {
                              MY_SECRET = "sensitive-value"
                            }
                          }
                          kms_key_arn = aws_kms_key.lambda_key.arn
                        }""")
                    self.findings.append(finding)
                
                # Check for VPC configuration for enhanced security
                if not re.search(r'vpc_config\s*{', func_config):
                    finding = SecurityFinding(
                        "LambdaVPCAccess",
                        "MEDIUM",
                        f"Lambda function '{func_name}' is not configured to run in a VPC",
                        None
                    )
                    finding.add_suggestion("""
                        Configure Lambda to run in a VPC for enhanced security:
                        resource "aws_lambda_function" "example" {
                          # ... other configuration ...
                          vpc_config {
                            subnet_ids         = [aws_subnet.private_1.id, aws_subnet.private_2.id]
                            security_group_ids = [aws_security_group.lambda_sg.id]
                          }
                        }""")
                    self.findings.append(finding)
        
        return self.findings