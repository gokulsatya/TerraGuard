# src/rules/database_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class RDSEncryptionRule(SecurityRule):
    """
    Checks if RDS databases are encrypted at rest.
    Database encryption is like keeping your sensitive documents in a safe -
    it protects your data even if someone gains physical access to the storage.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "RDSEncryptionDisabled"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_db_instance"' in content:
            # Check for storage encryption setting
            if not re.search(r'storage_encrypted\s*=\s*true', content):
                line_num = self._find_line_number(content, 'aws_db_instance')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "RDS instance is not configured for storage encryption",
                    line_num
                )
                finding.add_suggestion("""
                    Enable storage encryption for your RDS instance:
                    resource "aws_db_instance" "example" {
                      # ... other configuration ...
                      storage_encrypted = true
                      kms_key_id = aws_kms_key.example.arn  # Optional: Use a custom KMS key
                    }""")
                self.findings.append(finding)
        
        return self.findings

class RDSPublicAccessRule(SecurityRule):
    """
    Checks if RDS instances are publicly accessible.
    A publicly accessible database is like putting your filing cabinet on the street -
    it should almost never be done in production environments.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "RDSPubliclyAccessible"
        self.severity = "CRITICAL"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_db_instance"' in content:
            # Check for public accessibility setting
            if re.search(r'publicly_accessible\s*=\s*true', content):
                line_num = self._find_line_number(content, 'publicly_accessible')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "RDS instance is configured to be publicly accessible",
                    line_num
                )
                finding.add_suggestion("""
                    Disable public accessibility and use private subnets:
                    resource "aws_db_instance" "example" {
                      # ... other configuration ...
                      publicly_accessible = false
                      db_subnet_group_name = aws_db_subnet_group.private.name
                    }""")
                self.findings.append(finding)
        
        return self.findings

class RDSBackupRule(SecurityRule):
    """
    Checks if RDS instances have proper backup configurations.
    Database backups are like insurance - they protect you against data loss
    and should always be enabled with appropriate retention periods.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "RDSBackupDisabled"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_db_instance"' in content:
            # Check for backup configuration
            backup_disabled = re.search(r'backup_retention_period\s*=\s*0', content)
            if backup_disabled:
                line_num = self._find_line_number(content, 'backup_retention_period')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "RDS instance has backups disabled (retention period = 0)",
                    line_num
                )
                finding.add_suggestion("""
                    Enable backups with an appropriate retention period:
                    resource "aws_db_instance" "example" {
                      # ... other configuration ...
                      backup_retention_period = 7  # Retain backups for 7 days
                      backup_window = "03:00-04:00"  # Schedule backups during off-peak hours
                    }""")
                self.findings.append(finding)
        
        return self.findings