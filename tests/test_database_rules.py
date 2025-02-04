# tests/test_database_rules.py

import unittest
from src.rules.database_rules import RDSEncryptionRule, RDSPublicAccessRule, RDSBackupRule

class TestDatabaseSecurityRules(unittest.TestCase):
    def setUp(self):
        """Initialize all our database security rules before each test"""
        self.encryption_rule = RDSEncryptionRule()
        self.public_access_rule = RDSPublicAccessRule()
        self.backup_rule = RDSBackupRule()

    # Encryption Rule Tests
    def test_unencrypted_rds_detection(self):
        """Tests that we can detect an unencrypted RDS instance. This is important 
        because unencrypted databases pose a significant security risk if the underlying 
        storage is compromised."""
        terraform_content = '''
        resource "aws_db_instance" "unencrypted_db" {
            identifier = "myapp-production-db"
            engine     = "mysql"
            # Encryption not configured
        }
        '''
        
        findings = self.encryption_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1, "Should detect one unencrypted database")
        self.assertIn("not configured for storage encryption", findings[0].message)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_encrypted_rds_instance(self):
        """Tests that properly encrypted RDS instances are recognized as secure.
        We want to ensure we don't raise false positives for secure configurations."""
        terraform_content = '''
        resource "aws_db_instance" "encrypted_db" {
            identifier        = "myapp-production-db"
            engine           = "mysql"
            storage_encrypted = true
            kms_key_id       = aws_kms_key.db_encryption.arn
        }
        '''
        
        findings = self.encryption_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0, "Should not flag encrypted database")

    # Public Access Rule Tests
    def test_public_access_detection(self):
        """Tests detection of publicly accessible RDS instances. Public databases
        are rarely appropriate for production use and represent a critical security risk."""
        terraform_content = '''
        resource "aws_db_instance" "public_db" {
            identifier          = "myapp-db"
            publicly_accessible = true
        }
        '''
        
        findings = self.public_access_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1, "Should detect publicly accessible database")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("publicly accessible", findings[0].message.lower())

    def test_private_access_configuration(self):
        """Tests that properly configured private RDS instances pass validation.
        This represents the secure configuration we want to encourage."""
        terraform_content = '''
        resource "aws_db_instance" "private_db" {
            identifier          = "myapp-db"
            publicly_accessible = false
            db_subnet_group_name = aws_db_subnet_group.private.name
        }
        '''
        
        findings = self.public_access_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0, "Should not flag private database")

    # Backup Rule Tests
    def test_disabled_backups_detection(self):
        """Tests detection of disabled backups. Backups are crucial for disaster
        recovery and should never be disabled in production environments."""
        terraform_content = '''
        resource "aws_db_instance" "no_backup_db" {
            identifier = "myapp-db"
            backup_retention_period = 0
        }
        '''
        
        findings = self.backup_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1, "Should detect disabled backups")
        self.assertIn("backups disabled", findings[0].message)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_proper_backup_configuration(self):
        """Tests that RDS instances with proper backup configurations pass validation.
        This represents a secure backup configuration with appropriate retention."""
        terraform_content = '''
        resource "aws_db_instance" "backed_up_db" {
            identifier              = "myapp-db"
            backup_retention_period = 7
            backup_window           = "03:00-04:00"
        }
        '''
        
        findings = self.backup_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 0, "Should not flag database with backups enabled")

    def test_multiple_issues(self):
        """Tests detection of multiple issues in a single RDS instance. This helps
        ensure our rules can detect and report multiple problems simultaneously."""
        terraform_content = '''
        resource "aws_db_instance" "problematic_db" {
            identifier              = "myapp-db"
            publicly_accessible     = true
            backup_retention_period = 0
            # Missing encryption
        }
        '''
        
        # Check each rule individually
        encryption_findings = self.encryption_rule.analyze(terraform_content)
        public_findings = self.public_access_rule.analyze(terraform_content)
        backup_findings = self.backup_rule.analyze(terraform_content)
        
        self.assertEqual(len(encryption_findings), 1, "Should detect missing encryption")
        self.assertEqual(len(public_findings), 1, "Should detect public accessibility")
        self.assertEqual(len(backup_findings), 1, "Should detect disabled backups")

if __name__ == '__main__':
    unittest.main()