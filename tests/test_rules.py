# tests/test_rules.py

import unittest
from src.rules.base_rules import RulesEngine, S3PublicAccessRule, S3EncryptionRule
from src.rules.s3_rules import S3PublicAccessRule, S3EncryptionRule  # Changed import location
class TestSecurityRules(unittest.TestCase):
    def setUp(self):
        self.engine = RulesEngine()
        
    def test_s3_public_access_detection(self):
        """Test detection of public S3 buckets"""
        terraform_content = '''
        resource "aws_s3_bucket" "bad_bucket" {
            bucket = "my-public-bucket"
            acl    = "public-read"
        }
        '''
        
        findings = self.engine.analyze(terraform_content)
        
        # We should find at least one issue (public access)
        self.assertTrue(any(
            finding['message'] == "S3 bucket has public read access enabled"
            for finding in findings
        ))
        
    def test_s3_encryption_detection(self):
        """Test detection of unencrypted S3 buckets"""
        terraform_content = '''
        resource "aws_s3_bucket" "unencrypted_bucket" {
            bucket = "my-bucket"
        }
        '''
        
        findings = self.engine.analyze(terraform_content)
        
        # We should find at least one issue (missing encryption)
        self.assertTrue(any(
            finding['message'] == "S3 bucket is missing server-side encryption"
            for finding in findings
        ))
        
    def test_secure_s3_bucket(self):
        """Test a properly secured S3 bucket"""
        terraform_content = '''
        resource "aws_s3_bucket" "good_bucket" {
            bucket = "my-secure-bucket"
            
            server_side_encryption_configuration {
                rule {
                    apply_server_side_encryption_by_default {
                        sse_algorithm = "AES256"
                    }
                }
            }
        }
        '''
    # Add these test methods to the TestSecurityRules class in test_rules.py

    def test_multiple_issues_detection(self):
        """Test detection of multiple issues in a single resource"""
        terraform_content = '''
        resource "aws_s3_bucket" "problematic_bucket" {
            bucket = "my-risky-bucket"
            acl    = "public-read"
            # Missing encryption configuration
        }
        '''
    
        findings = self.engine.analyze(terraform_content)
        # Should find both public access and missing encryption
        self.assertEqual(len(findings), 2)

    def test_malformed_terraform(self):
        """Test handling of malformed Terraform configurations"""
        terraform_content = '''
        resource "aws_s3_bucket" "broken_config" {
            bucket = "my-bucket"
            # Missing closing brace
        '''
    
        findings = self.engine.analyze(terraform_content)
        # Should handle malformed content gracefully
        self.assertEqual(len(findings), 0)

    def test_empty_configuration(self):
        """Test handling of empty configurations"""
        findings = self.engine.analyze("")
        self.assertEqual(len(findings), 0)    
        
        findings = self.engine.analyze(terraform_content)
        
        # We should find no issues
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()