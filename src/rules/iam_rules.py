# src/rules/iam_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re
import json

class IAMAdminPolicyRule(SecurityRule):
    """
    Rule to check for IAM policies that might grant excessive administrative privileges.
    Think of administrative privileges like having a master key to every room in a building - 
    they should be granted very carefully and only when absolutely necessary.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "IAMExcessiveAdmin"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Look for IAM policy resources
        if 'resource "aws_iam_policy"' in content or 'resource "aws_iam_role_policy"' in content:
            # Check for overly permissive actions
            dangerous_patterns = [
                (r'"Action"\s*:\s*"(\*|iam:\*)"', "full administrative"),
                (r'"Resource"\s*:\s*"\*"', "all resources"),
                (r'"Effect"\s*:\s*"Allow".+?(\*|iam:\*)', "full IAM access")
            ]
            
            for pattern, description in dangerous_patterns:
                if re.search(pattern, content):
                    line_num = self._find_line_number(content, pattern.split('"')[1])
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"IAM policy grants {description} access",
                        line_num
                    )
                    finding.add_suggestion(
                        """Consider restricting permissions to only what is needed:
                        {
                          "Version": "2012-10-17",
                          "Statement": [
                            {
                              "Effect": "Allow",
                              "Action": [
                                "s3:GetObject",
                                "s3:ListBucket"
                              ],
                              "Resource": [
                                "arn:aws:s3:::specific-bucket",
                                "arn:aws:s3:::specific-bucket/*"
                              ]
                            }
                          ]
                        }"""
                    )
                    self.findings.append(finding)
        
        return self.findings


class IAMUserCredentialsRule(SecurityRule):
    """
    Rule to check for IAM user credentials and access keys defined in Terraform.
    Hard-coding credentials in your configuration is like writing your password
    on a sticky note - it's never a good security practice!
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "IAMCredentialsExposed"
        self.severity = "CRITICAL"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Check for hard-coded credentials
        credential_patterns = [
            (r'aws_access_key_id\s*=\s*"[^"]+"', "AWS access key"),
            (r'aws_secret_access_key\s*=\s*"[^"]+"', "AWS secret key"),
            (r'password\s*=\s*"[^"]+"', "password"),
            (r'secret\s*=\s*"[^"]+"', "secret")
        ]
        
        for pattern, cred_type in credential_patterns:
            if re.search(pattern, content):
                line_num = self._find_line_number(content, pattern.split('=')[0])
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    f"Hard-coded {cred_type} found in configuration",
                    line_num
                )
                finding.add_suggestion(
                    """Never hard-code credentials in your Terraform files.
                    Instead, use:
                    1. Environment variables
                    2. AWS credentials file (~/.aws/credentials)
                    3. Instance profiles for EC2 instances
                    4. Secure secret management services"""
                )
                self.findings.append(finding)
        
        return self.findings


class IAMRolePermissionsRule(SecurityRule):
    """
    Rule to check if IAM roles follow the principle of least privilege.
    Think of permissions like keys to different rooms - each person should
    only have keys to the rooms they need to access for their job.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "IAMRolePermissions"
        self.severity = "MEDIUM"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_iam_role"' in content:
            # Check for overly permissive trust relationships
            if re.search(r'Principal\s*:\s*{\s*"AWS"\s*:\s*"\*"', content):
                line_num = self._find_line_number(content, '"AWS"')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "IAM role allows assumption by any AWS principal",
                    line_num
                )
                finding.add_suggestion(
                    """Restrict role assumption to specific AWS accounts or services:
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Principal": {
                            "AWS": "arn:aws:iam::ACCOUNT-ID:root"
                          },
                          "Action": "sts:AssumeRole"
                        }
                      ]
                    }"""
                )
                self.findings.append(finding)
        
        return self.findings