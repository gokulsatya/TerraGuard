# src/rules/s3_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class S3PublicAccessRule(SecurityRule):
    """Rule to check for S3 buckets with public access enabled"""
    
    def analyze(self, content: str) -> list:
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
    
    def analyze(self, content: str) -> list:
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