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
        
if __name__ == '__main__':
    unittest.main()