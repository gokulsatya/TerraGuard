# tests/test_iam_rules.py

import unittest
from src.rules.iam_rules import IAMAdminPolicyRule, IAMUserCredentialsRule, IAMRolePermissionsRule

class TestIAMSecurityRules(unittest.TestCase):
    def setUp(self):
        self.admin_rule = IAMAdminPolicyRule()
        self.credentials_rule = IAMUserCredentialsRule()
        self.role_rule = IAMRolePermissionsRule()
    
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

if __name__ == '__main__':
    unittest.main()