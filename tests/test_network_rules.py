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
    
    # Add these methods to the TestNetworkSecurityRules class

    def test_multiple_security_groups(self):
        """Test handling of multiple security groups"""
        terraform_content = '''
        resource "aws_security_group" "group1" {
            ingress {
                cidr_blocks = ["0.0.0.0/0"]
            }
        }
        resource "aws_security_group" "group2" {
            ingress {
                cidr_blocks = ["10.0.0.0/8"]
            }
        }
        '''
    
        findings = self.rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1)

    def test_invalid_cidr_blocks(self):
        """Test handling of invalid CIDR blocks"""
        terraform_content = '''
        resource "aws_security_group" "invalid" {
            ingress {
                cidr_blocks = ["invalid-cidr"]
            }
        }
        '''
    
        findings = self.rule.analyze(terraform_content)
        # Should handle invalid CIDR blocks gracefully
        self.assertEqual(len(findings), 0)

# Add these test classes to tests/test_network_rules.py

class TestPortExposureRule(unittest.TestCase):
    def setUp(self):
        self.rule = PortExposureRule()
    
    def test_sensitive_port_exposure(self):
        """Test detection of exposed sensitive ports"""
        terraform_content = '''
        resource "aws_security_group" "exposed_ports" {
            name = "exposed-ports"
            
            ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
            }
        }
        '''
        
        findings = self.rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1)
        self.assertTrue(any("SSH port (22)" in finding.message for finding in findings))

class TestNetworkACLRule(unittest.TestCase):
    def setUp(self):
        self.rule = NetworkACLRule()
    
    def test_permissive_nacl(self):
        """Test detection of overly permissive NACLs"""
        terraform_content = '''
        resource "aws_network_acl" "open_nacl" {
            vpc_id = aws_vpc.main.id
            
            ingress {
                protocol   = "-1"
                rule_no    = 50
                action     = "allow"
                cidr_block = "0.0.0.0/0"
                from_port  = 0
                to_port    = 0
            }
        }
        '''
        
        findings = self.rule.analyze(terraform_content)
        self.assertEqual(len(findings), 2)  # Should find both permissive rule and missing deny

if __name__ == '__main__':
    unittest.main()