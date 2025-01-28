# src/rules/kms_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class KMSKeyRotationRule(SecurityRule):
    """
    Verifies that KMS keys are configured to rotate automatically. Key rotation is 
    a critical security practice that helps minimize the impact of potential key
    compromises by regularly generating new cryptographic material.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "KMSKeyRotationDisabled"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Look for KMS key resources
        if 'resource "aws_kms_key"' in content:
            # Check for key rotation setting - it should be explicitly set to true
            if re.search(r'enable_key_rotation\s*=\s*false', content) or \
               not re.search(r'enable_key_rotation\s*=\s*true', content):
                line_num = self._find_line_number(content, 'aws_kms_key')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "KMS key does not have automatic rotation enabled",
                    line_num
                )
                finding.add_suggestion("""
                    Enable automatic key rotation to enhance security:
                    resource "aws_kms_key" "example" {
                      description         = "Customer managed key for encryption"
                      enable_key_rotation = true
                      
                      # Consider adding deletion window
                      deletion_window_in_days = 30
                    }""")
                self.findings.append(finding)
        
        return self.findings

class KMSKeyDeletionWindowRule(SecurityRule):
    """
    Checks if KMS keys have an appropriate deletion window configured. This window
    provides a safety period during which accidentally deleted keys can be recovered,
    preventing unintentional data loss.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "KMSKeyDeletionWindow"
        self.severity = "MEDIUM"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_kms_key"' in content:
            # Check for deletion window - recommend at least 7 days
            deletion_window = re.search(r'deletion_window_in_days\s*=\s*(\d+)', content)
            if not deletion_window or int(deletion_window.group(1)) < 7:
                line_num = self._find_line_number(content, 'aws_kms_key')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "KMS key has insufficient or no deletion window configured",
                    line_num
                )
                finding.add_suggestion("""
                    Configure an appropriate deletion window (minimum 7 days recommended):
                    resource "aws_kms_key" "example" {
                      description             = "Customer managed key"
                      deletion_window_in_days = 7  # Minimum recommended value
                    }""")
                self.findings.append(finding)
        
        return self.findings

class KMSKeyUsageRule(SecurityRule):
    """
    Analyzes how KMS keys are being used across the infrastructure. This helps
    ensure that encryption is being properly implemented for sensitive resources.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "KMSKeyUsage"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Check for resources that should be using KMS encryption
        sensitive_resources = [
            ('resource "aws_s3_bucket"', 'server_side_encryption_configuration'),
            ('resource "aws_rds_cluster"', 'kms_key_id'),
            ('resource "aws_ebs_volume"', 'kms_key_id'),
            ('resource "aws_secretsmanager_secret"', 'kms_key_id')
        ]
        
        for resource_type, encryption_field in sensitive_resources:
            if resource_type in content:
                # Find all instances of this resource type
                resource_blocks = re.finditer(
                    f'{resource_type}\\s+"([^"]+)"\\s+{{([^}}]+)}}', 
                    content, 
                    re.DOTALL
                )
                
                for match in resource_blocks:
                    resource_name = match.group(1)
                    resource_config = match.group(2)
                    
                    if encryption_field not in resource_config:
                        line_num = self._find_line_number(content, resource_name)
                        finding = SecurityFinding(
                            self.rule_id,
                            self.severity,
                            f"{resource_type} '{resource_name}' is not using KMS encryption",
                            line_num
                        )
                        finding.add_suggestion(f"""
                            Enable KMS encryption for this resource:
                            {resource_type} "{resource_name}" {{
                              # ... other configuration ...
                              {encryption_field} = aws_kms_key.example.id
                            }}""")
                        self.findings.append(finding)
        
        return self.findings