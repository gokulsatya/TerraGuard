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

class S3LoggingRule(SecurityRule):
    """
    Rule to check if S3 buckets have logging enabled.
    Logging is crucial for security auditing and monitoring bucket access.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "S3LoggingDisabled"
        self.severity = "MEDIUM"
    
    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_s3_bucket"' in content:
            # Check for logging configuration
            bucket_blocks = re.finditer(
                r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for match in bucket_blocks:
                bucket_name = match.group(1)
                bucket_config = match.group(2)
                
                # Look for logging block
                if 'logging' not in bucket_config:
                    line_num = self._find_line_number(content, bucket_name)
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"S3 bucket '{bucket_name}' does not have logging enabled",
                        line_num
                    )
                    finding.add_suggestion("""
                        Enable logging for your S3 bucket:
                        resource "aws_s3_bucket" "example" {
                          # ... other configuration ...
                          
                          logging {
                            target_bucket = aws_s3_bucket.log_bucket.id
                            target_prefix = "log/"
                          }
                        }
                        
                        # Don't forget to create a separate bucket for logs
                        resource "aws_s3_bucket" "log_bucket" {
                          bucket = "example-logs"
                          # ... appropriate security configurations ...
                        }""")
                    self.findings.append(finding)
        
        return self.findings

class S3VersioningRule(SecurityRule):
    """
    Rule to check if S3 buckets have versioning enabled.
    Versioning helps protect against accidental or malicious deletion and modifications.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "S3VersioningDisabled"
        self.severity = "MEDIUM"
    
    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_s3_bucket"' in content:
            # Check for versioning configuration
            bucket_blocks = re.finditer(
                r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for match in bucket_blocks:
                bucket_name = match.group(1)
                bucket_config = match.group(2)
                
                # Look for versioning block and ensure it's enabled
                versioning_disabled = (
                    'versioning' not in bucket_config or
                    re.search(r'versioning\s*{\s*enabled\s*=\s*false', bucket_config)
                )
                
                if versioning_disabled:
                    line_num = self._find_line_number(content, bucket_name)
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"S3 bucket '{bucket_name}' does not have versioning enabled",
                        line_num
                    )
                    finding.add_suggestion("""
                        Enable versioning for your S3 bucket:
                        resource "aws_s3_bucket" "example" {
                          # ... other configuration ...
                          
                          versioning {
                            enabled = true
                          }
                        }""")
                    self.findings.append(finding)
        
        return self.findings
