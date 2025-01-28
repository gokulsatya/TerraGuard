# tests/test_rules.py

import unittest
from src.rules.base_rules import RulesEngine, S3PublicAccessRule, S3EncryptionRule

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
        
        findings = self.engine.analyze(terraform_content)
        
        # We should find no issues
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()