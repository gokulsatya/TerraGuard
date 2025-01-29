# tests/test_iam_rules.py

import unittest
from src.rules.iam_rules import (
    IAMAdminPolicyRule,
    IAMUserCredentialsRule,
    IAMRolePermissionsRule,
    IAMCrossAccountAccessRule,
    IAMPasswordPolicyRule
)
class TestIAMSecurityRules(unittest.TestCase):
    def setUp(self):
        self.admin_rule = IAMAdminPolicyRule()
        self.credentials_rule = IAMUserCredentialsRule()
        self.role_rule = IAMRolePermissionsRule()
        self.cross_account_rule = IAMCrossAccountAccessRule()
        self.password_policy_rule = IAMPasswordPolicyRule()
    
    def test_admin_policy_detection(self):
        """Test detection of overly permissive admin policies"""
        terraform_content = '''
        resource "aws_iam_policy" "admin_policy" {
            name = "full-admin-access"
            policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                    {
                        Effect = "Allow"
                        Action = "*"
                        Resource = "*"
                    }
                ]
            })
        }
        '''
        
        findings = self.admin_rule.analyze(terraform_content)
        
        # Should find issues with both Action and Resource being too permissive
        self.assertGreaterEqual(len(findings), 1)
        messages = [f.message for f in findings]
        self.assertTrue(any("administrative access" in msg for msg in messages))
    
    def test_exposed_credentials_detection(self):
        """Test detection of hard-coded credentials"""
        terraform_content = '''
        provider "aws" {
            region = "us-west-2"
            aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
            aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
        '''
        
        findings = self.credentials_rule.analyze(terraform_content)
        
        # Should find both access key and secret key
        self.assertEqual(len(findings), 2)
        self.assertTrue(
            any("access key" in finding.message for finding in findings)
        )
        self.assertTrue(
            any("secret key" in finding.message for finding in findings)
        )
    
    def test_role_permissions(self):
        """Test detection of overly permissive role trust relationships"""
        terraform_content = '''
        resource "aws_iam_role" "example" {
            name = "example-role"
            
            assume_role_policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                    {
                        Effect = "Allow"
                        Principal = {
                            AWS = "*"
                        }
                        Action = "sts:AssumeRole"
                    }
                ]
            })
        }
        '''
        
        findings = self.role_rule.analyze(terraform_content)
        
        # Should find the overly permissive trust relationship
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            "allows assumption by any AWS principal" in findings[0].message
        )

# tests/test_iam_rules.py

import unittest
from src.rules.iam_rules import (
    IAMAdminPolicyRule,
    IAMUserCredentialsRule,
    IAMRolePermissionsRule,
    IAMCrossAccountAccessRule,
    IAMPasswordPolicyRule
)

class TestIAMSecurityRules(unittest.TestCase):
    def setUp(self):
        # Initialize all rule instances we'll test
        self.admin_rule = IAMAdminPolicyRule()
        self.credentials_rule = IAMUserCredentialsRule()
        self.role_rule = IAMRolePermissionsRule()
        self.cross_account_rule = IAMCrossAccountAccessRule()
        self.password_policy_rule = IAMPasswordPolicyRule()

    # Previous test methods remain unchanged...
    
    def test_cross_account_access_detection(self):
        """Test detection of risky cross-account access configurations"""
        # Test case 1: Role allowing any AWS account
        terraform_content = '''
        resource "aws_iam_role" "risky_role" {
            name = "risky-cross-account-role"
            
            assume_role_policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                    {
                        Effect = "Allow"
                        Principal = {
                            AWS = "*"  # This is dangerous!
                        }
                        Action = "sts:AssumeRole"
                    }
                ]
            })
        }
        '''
        
        findings = self.cross_account_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            "Cross-account access granted to any AWS account" in findings[0].message
        )

        # Test case 2: Properly restricted cross-account access
        terraform_content = '''
        resource "aws_iam_role" "secure_role" {
            name = "secure-cross-account-role"
            
            assume_role_policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                    {
                        Effect = "Allow"
                        Principal = {
                            AWS = "arn:aws:iam::123456789012:root"
                        }
                        Action = "sts:AssumeRole"
                        Condition = {
                            StringEquals = {
                                "sts:ExternalId": "SecureExternalId"
                            }
                        }
                    }
                ]
            })
        }
        '''
        
        findings = self.cross_account_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0)

    def test_password_policy_validation(self):
        """Test validation of IAM password policy settings"""
        # Test case 1: Missing password policy
        terraform_content = '''
        # No password policy defined
        resource "aws_iam_user" "example" {
            name = "example-user"
        }
        '''
        
        findings = self.password_policy_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1)
        self.assertTrue("No IAM password policy is defined" in findings[0].message)

        # Test case 2: Weak password policy
        terraform_content = '''
        resource "aws_iam_account_password_policy" "weak" {
            minimum_password_length        = 8
            require_lowercase_characters   = false
            require_numbers               = true
            require_uppercase_characters   = false
            require_symbols               = false
            password_reuse_prevention     = 5
            max_password_age             = 180
        }
        '''
        
        findings = self.password_policy_rule.analyze(terraform_content)
        self.assertGreater(len(findings), 0)
        messages = [f.message for f in findings]
        self.assertTrue(any("length should be at least 14" in msg for msg in messages))
        self.assertTrue(any("should require symbols" in msg for msg in messages))

        # Test case 3: Strong password policy
        terraform_content = '''
        resource "aws_iam_account_password_policy" "strong" {
            minimum_password_length        = 14
            require_lowercase_characters   = true
            require_numbers               = true
            require_uppercase_characters   = true
            require_symbols               = true
            password_reuse_prevention     = 24
            max_password_age             = 90
            allow_users_to_change_password = true
        }
        '''
        
        findings = self.password_policy_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0)

    def test_cross_account_with_external_id(self):
        """Test cross-account access configurations with external ID"""
        terraform_content = '''
        resource "aws_iam_role" "cross_account" {
            name = "cross-account-role"
            
            assume_role_policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                    {
                        Effect = "Allow"
                        Principal = {
                            AWS = "arn:aws:iam::123456789012:root"
                        }
                        Action = "sts:AssumeRole"
                        Condition = {
                            StringEquals = {
                                "sts:ExternalId": "${var.external_id}"
                            }
                        }
                    }
                ]
            })
        }
        '''
        
        findings = self.cross_account_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0)

    def test_password_policy_edge_cases(self):
        """Test password policy validation with edge cases"""
        # Test case 1: Policy with exactly minimum values
        terraform_content = '''
        resource "aws_iam_account_password_policy" "edge_case" {
            minimum_password_length        = 14
            require_lowercase_characters   = true
            require_numbers               = true
            require_uppercase_characters   = true
            require_symbols               = true
            password_reuse_prevention     = 24
            max_password_age             = 90
        }
        '''
        
        findings = self.password_policy_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0)

        # Test case 2: Policy with missing fields
        terraform_content = '''
        resource "aws_iam_account_password_policy" "incomplete" {
            minimum_password_length        = 14
            require_lowercase_characters   = true
            # Missing other required fields
        }
        '''
        
        findings = self.password_policy_rule.analyze(terraform_content)
        self.assertGreater(len(findings), 0)

if __name__ == '__main__':
    unittest.main()