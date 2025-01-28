# src/rules/base_rules.py

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from .network_rules import SecurityGroupRule

class SecurityFinding:
    """Represents a security issue found in Terraform code"""
    
    def __init__(self, rule_id: str, severity: str, message: str, line_number: int = None):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.line_number = line_number
        self.suggested_fix = None

    def add_suggestion(self, fix: str):
        """Adds a suggested fix for the security issue"""
        self.suggested_fix = fix

    def to_dict(self) -> Dict[str, Any]:
        """Converts the finding to a dictionary format"""
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'message': self.message,
            'line_number': self.line_number,
            'suggested_fix': self.suggested_fix
        }

class SecurityRule(ABC):
    """Base class for all security rules"""
    
    def __init__(self):
        self.rule_id = self.__class__.__name__
        self.severity = "HIGH"
        self.findings: List[SecurityFinding] = []

    @abstractmethod
    def analyze(self, content: str) -> List[SecurityFinding]:
        """Analyzes Terraform content and returns a list of findings"""
        pass

    def _find_line_number(self, content: str, pattern: str) -> int:
        """Helper method to find the line number where a pattern appears"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return None

class S3PublicAccessRule(SecurityRule):
    """Rule to check for S3 buckets with public access enabled"""
    
    def analyze(self, content: str) -> List[SecurityFinding]:
        # Look for S3 buckets with public access
        public_access_pattern = r'acl\s*=\s*"public-read"'
        if re.search(public_access_pattern, content):
            line_num = self._find_line_number(content, 'public-read')
            finding = SecurityFinding(
                self.rule_id,
                self.severity,
                "S3 bucket has public read access enabled",
                line_num
            )
            finding.add_suggestion(
                "Remove the public-read ACL or replace with private ACL"
            )
            self.findings.append(finding)
        return self.findings

class S3EncryptionRule(SecurityRule):
    """Rule to check for S3 buckets without encryption"""
    
    def analyze(self, content: str) -> List[SecurityFinding]:
        # First, check if this content contains an S3 bucket
        if 'resource "aws_s3_bucket"' in content:
            # Check for encryption configuration
            encryption_pattern = r'server_side_encryption_configuration'
            if not re.search(encryption_pattern, content):
                line_num = self._find_line_number(content, 'aws_s3_bucket')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "S3 bucket is missing server-side encryption",
                    line_num
                )
                finding.add_suggestion("""
                Add encryption configuration:
                server_side_encryption_configuration {
                    rule {
                        apply_server_side_encryption_by_default {
                            sse_algorithm = "AES256"
                        }
                    }
                }""")
                self.findings.append(finding)
        return self.findings

class RulesEngine:
    """Main engine that applies security rules to Terraform content"""
    
    def __init__(self):
        self.rules: List[SecurityRule] = []
        # Register default rules
        self.register_rule(S3PublicAccessRule())
        self.register_rule(S3EncryptionRule())
        self.register_rule(SecurityGroupRule())  # Add our new rule
        
    def register_rule(self, rule: SecurityRule):
        """Adds a new rule to the engine"""
        self.rules.append(rule)

    def analyze(self, content: str) -> List[Dict[str, Any]]:
        """
        Analyzes Terraform content using all registered rules
        
        Args:
            content (str): Terraform configuration content
            
        Returns:
            List[Dict]: List of findings from all rules
        """
        all_findings = []
        for rule in self.rules:
            findings = rule.analyze(content)
            all_findings.extend([f.to_dict() for f in findings])
        return all_findings