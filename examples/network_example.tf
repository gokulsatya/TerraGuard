# tests/test_network_rules.py

import unittest
from src.rules.network_rules import SecurityGroupRule

class TestNetworkSecurityRules(unittest.TestCase):
    def setUp(self):
        self.rule = SecurityGroupRule()
        
    def test_open_security_group_detection(self):
        """Test detection of security groups with open access"""
        terraform_content = '''
        resource "aws_security_group" "open_group" {
            name = "open-to-world"
            
            ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
            }
        }
        '''
        
        findings = self.rule.analyze(terraform_content)
        
        # We should find one issue (open access)
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            any("Security group allows access from any IP address" in 
                finding.message for finding in findings)
        )
        
    def test_restricted_security_group(self):
        """Test a properly restricted security group"""
        terraform_content = '''
        resource "aws_security_group" "restricted_group" {
            name = "restricted-access"
            
            ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["192.168.1.0/24"]
            }
        }
        '''
        
        findings = self.rule.analyze(terraform_content)
        
        # We should find no issues
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()