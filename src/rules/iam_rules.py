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

        if 'resource "aws_iam_policy"' in content:
            # Check for various overly permissive patterns
            dangerous_patterns = [
                (r'"Action"\s*:\s*"\*"', "allows all actions"),
                (r'"Action"\s*:\s*\[\s*"\*"\s*\]', "allows all actions"),
                (r'"Resource"\s*:\s*"\*"', "applies to all resources"),
                (r'"Resource"\s*:\s*\[\s*"\*"\s*\]', "applies to all resources"),
                (r'"Effect"\s*:\s*"Allow".*"Principal"\s*:\s*"\*"', "allows any principal")
            ]

            for pattern, message in dangerous_patterns:
                if re.search(pattern, content, re.MULTILINE | re.DOTALL):
                    line_num = self._find_line_number(content, 'aws_iam_policy')
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"IAM policy {message}, granting excessive permissions",
                        line_num
                    )
                    finding.add_suggestion(
                        """Restrict permissions to only what is needed:
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

# src/rules/iam_rules.py - Update the IAMRolePermissionsRule class
    def analyze(self, content: str) -> list:
        self.findings = []
    
        if 'resource "aws_iam_role"' in content:
            # Check for overly permissive trust relationships
            if '"AWS"' in content and '"*"' in content:
                line_num = self._find_line_number(content, 'aws_iam_role')
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
class IAMPasswordPolicyRule(SecurityRule):
    """
    Rule to validate IAM password policy settings.
    Ensures that password policies meet security best practices
    for length, complexity, and rotation requirements.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "IAMPasswordPolicy"
        self.severity = "MEDIUM"
        
        # Define baseline password policy requirements
        self.min_password_length = 14
        self.require_symbols = True
        self.require_numbers = True
        self.require_uppercase = True
        self.require_lowercase = True
        self.password_reuse_prevention = 24
        self.max_password_age = 90

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_iam_account_password_policy"' in content:
            # Check various password policy settings
            policy_checks = [
                (r'minimum_password_length\s*=\s*(\d+)',
                 lambda x: int(x) >= self.min_password_length,
                 f"Password length should be at least {self.min_password_length} characters"),
                
                (r'require_symbols\s*=\s*(true|false)',
                 lambda x: x.lower() == 'true',
                 "Password policy should require symbols"),
                
                (r'require_numbers\s*=\s*(true|false)',
                 lambda x: x.lower() == 'true',
                 "Password policy should require numbers"),
                
                (r'require_uppercase_characters\s*=\s*(true|false)',
                 lambda x: x.lower() == 'true',
                 "Password policy should require uppercase characters"),
                
                (r'require_lowercase_characters\s*=\s*(true|false)',
                 lambda x: x.lower() == 'true',
                 "Password policy should require lowercase characters"),
                
                (r'password_reuse_prevention\s*=\s*(\d+)',
                 lambda x: int(x) >= self.password_reuse_prevention,
                 f"Password reuse prevention should be set to at least {self.password_reuse_prevention}"),
                
                (r'max_password_age\s*=\s*(\d+)',
                 lambda x: int(x) <= self.max_password_age,
                 f"Maximum password age should be {self.max_password_age} days or less")
            ]

            for pattern, validator, message in policy_checks:
                match = re.search(pattern, content)
                if not match or not validator(match.group(1)):
                    line_num = self._find_line_number(content, 'aws_iam_account_password_policy')
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        message,
                        line_num
                    )
                    finding.add_suggestion("""
                        Configure a strong password policy:
                        resource "aws_iam_account_password_policy" "strict" {
                          minimum_password_length        = 14
                          require_lowercase_characters   = true
                          require_uppercase_characters   = true
                          require_numbers               = true
                          require_symbols               = true
                          allow_users_to_change_password = true
                          password_reuse_prevention     = 24
                          max_password_age             = 90
                        }""")
                    self.findings.append(finding)
        else:
            # No password policy defined
            finding = SecurityFinding(
                self.rule_id,
                self.severity,
                "No IAM password policy is defined",
                None
            )
            finding.add_suggestion("""
                Define a password policy with security best practices:
                resource "aws_iam_account_password_policy" "strict" {
                  minimum_password_length        = 14
                  require_lowercase_characters   = true
                  require_uppercase_characters   = true
                  require_numbers               = true
                  require_symbols               = true
                  allow_users_to_change_password = true
                  password_reuse_prevention     = 24
                  max_password_age             = 90
                }""")
            self.findings.append(finding)

        return self.findings