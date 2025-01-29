# tests/test_file_reader.py

import unittest
from src.parser.file_reader import TerraformFileReader

class TestTerraformFileReader(unittest.TestCase):
    def setUp(self):
        self.reader = TerraformFileReader()
        
    def test_read_nonexistent_file(self):
        """Test handling of non-existent files"""
        result = self.reader.read_file("nonexistent.tf")
        self.assertFalse(result)
        self.assertTrue(any("File not found" in error for error in self.reader.get_errors()))
        
    def test_terraform_file_validation(self):
        """Test Terraform file validation"""
        # Create a temporary test file
        with open("test_config.tf", "w") as f:
            f.write('resource "aws_s3_bucket" "test" {\n  bucket = "test-bucket"\n}')
        
        # Test reading and validation
        self.reader.read_file("test_config.tf")
        self.assertTrue(self.reader.is_terraform_file())
        
        # Clean up
        import os
        os.remove("test_config.tf")
    
    # Add these methods to the TestTerraformFileReader class

    def test_empty_file(self):
        """Test handling of empty files"""
        with open("empty.tf", "w") as f:
            pass
    
        self.reader.read_file("empty.tf")
        self.assertFalse(self.reader.is_terraform_file())
        import os
        os.remove("empty.tf")

    def test_malformed_content(self):
        """Test handling of malformed Terraform content"""
        with open("malformed.tf", "w") as f:
            f.write('This is not valid Terraform content')
    
        self.reader.read_file("malformed.tf")
        self.assertFalse(self.reader.is_terraform_file())
        import os
        os.remove("malformed.tf")

    # tests/test_file_reader.py - Update the test_permission_handling method
    def test_permission_handling(self):
        """Test handling of permission issues"""
        import sys
        if sys.platform != "win32":
            # Unix-specific permission test
            with open("readonly.tf", "w") as f:
                f.write('resource "aws_s3_bucket" "test" {}')
        
            import os
            os.chmod("readonly.tf", 0o000)
            result = self.reader.read_file("readonly.tf")
            self.assertFalse(result)
            os.chmod("readonly.tf", 0o666)
            os.remove("readonly.tf")
        else:
            # Windows alternative test
            self.skipTest("Skipping permission test on Windows")
if __name__ == '__main__':
    unittest.main()