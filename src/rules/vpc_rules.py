# src/rules/vpc_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class VPCFlowLogsRule(SecurityRule):
    """
    Checks if VPC Flow Logs are enabled for network monitoring and security analysis.
    Flow logs are like security cameras for your network traffic - they help you 
    track who's trying to communicate with your resources.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "VPCFlowLogsDisabled"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Check if this is a VPC resource
        if 'resource "aws_vpc"' in content:
            # Look for flow logs configuration
            vpc_blocks = re.findall(r'resource\s+"aws_vpc"\s+"([^"]+)"\s+{[^}]+}', content)
            
            for vpc in vpc_blocks:
                if not re.search(r'resource\s+"aws_flow_log"\s+.*vpc_id\s+=\s+.*' + vpc, content):
                    line_num = self._find_line_number(content, f'resource "aws_vpc" "{vpc}"')
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"VPC '{vpc}' does not have flow logs enabled",
                        line_num
                    )
                    finding.add_suggestion("""
                    Enable VPC Flow Logs to monitor network traffic:
                    resource "aws_flow_log" "example" {
                      vpc_id = aws_vpc.example.id
                      traffic_type = "ALL"
                      log_destination_type = "cloud-watch-logs"
                      log_destination = aws_cloudwatch_log_group.example.arn
                    }""")
                    self.findings.append(finding)
        
        return self.findings

class VPCDefaultSecurityGroupRule(SecurityRule):
    """
    Checks if the default security group of a VPC has been properly restricted.
    The default security group is like the basic lock on your front door - 
    it needs to be configured properly for basic security.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "VPCDefaultSGOpen"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_default_security_group"' in content:
            # Check for open ingress/egress rules
            ingress_pattern = r'ingress\s*{[^}]*0\.0\.0\.0/0[^}]*}'
            egress_pattern = r'egress\s*{[^}]*0\.0\.0\.0/0[^}]*}'
            
            if re.search(ingress_pattern, content) or re.search(egress_pattern, content):
                line_num = self._find_line_number(content, 'aws_default_security_group')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "Default security group has overly permissive rules",
                    line_num
                )
                finding.add_suggestion("""
                    Restrict the default security group rules:
                    resource "aws_default_security_group" "example" {
                      vpc_id = aws_vpc.example.id
                      
                      # Restrict ingress to specific IPs/security groups
                      ingress {
                        from_port = 443
                        to_port = 443
                        protocol = "tcp"
                        cidr_blocks = ["10.0.0.0/16"]  # Internal network only
                      }
                      
                      # Control egress traffic
                      egress {
                        from_port = 0
                        to_port = 0
                        protocol = "-1"
                        cidr_blocks = ["10.0.0.0/16"]  # Internal network only
                      }
                    }""")
                self.findings.append(finding)
        
        return self.findings

class VPCSubnetPublicIPRule(SecurityRule):
    """
    Checks if subnets are configured to automatically assign public IPs.
    Public IPs are like putting your resources on display - sometimes necessary,
    but should be carefully controlled.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "VPCSubnetAutoPublicIP"
        self.severity = "MEDIUM"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Look for subnets with auto public IP assignment
        if 'resource "aws_subnet"' in content:
            public_ip_pattern = r'map_public_ip_on_launch\s*=\s*true'
            if re.search(public_ip_pattern, content):
                line_num = self._find_line_number(content, 'map_public_ip_on_launch')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "Subnet is configured to automatically assign public IPs",
                    line_num
                )
                finding.add_suggestion("""
                    Disable automatic public IP assignment unless specifically required:
                    resource "aws_subnet" "example" {
                      vpc_id     = aws_vpc.example.id
                      cidr_block = "10.0.1.0/24"
                      
                      # Disable automatic public IP assignment
                      map_public_ip_on_launch = false
                    }""")
                self.findings.append(finding)
        
        return self.findings