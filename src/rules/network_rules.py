# src/rules/network_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class SecurityGroupRule(SecurityRule):
    """
    Rule to check for overly permissive security group rules.
    This is like checking if your house's front door is open to everyone!
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "SecurityGroupOpenAccess"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        # Reset findings for this analysis
        self.findings = []
        
        # Look for security group resources
        if 'resource "aws_security_group"' in content:
            # Check for overly permissive ingress rules
            # This pattern looks for ingress rules with 0.0.0.0/0
            open_access_pattern = r'(ingress|cidr_blocks)\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'
            if re.search(open_access_pattern, content):
                line_num = self._find_line_number(content, '0.0.0.0/0')
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "Security group allows access from any IP address (0.0.0.0/0)",
                    line_num
                )
                finding.add_suggestion(
                    """Consider restricting access to specific IP ranges:
                    ingress {
                        cidr_blocks = ["YOUR-IP-RANGE/32"]  # Example: "192.168.1.0/24"
                        # ... other configuration ...
                    }"""
                )
                self.findings.append(finding)
                
        return self.findings
class PortExposureRule(SecurityRule):
    """
    Analyzes security group rules for potentially dangerous port exposures.
    Checks for commonly exploited ports that shouldn't be publicly accessible.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "PortExposureCheck"
        self.severity = "HIGH"
        
        # Define sensitive ports that should be restricted
        self.sensitive_ports = {
            22: "SSH",
            3389: "RDP",
            1433: "MS SQL",
            3306: "MySQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch",
            5432: "PostgreSQL"
        }

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Look for security group ingress rules
        if 'resource "aws_security_group"' in content:
            # Find all security group blocks
            sg_blocks = re.finditer(
                r'resource\s+"aws_security_group"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for sg_match in sg_blocks:
                sg_name = sg_match.group(1)
                sg_config = sg_match.group(2)
                
                # Find all ingress rules
                ingress_blocks = re.finditer(
                    r'ingress\s*{([^}]+)}',
                    sg_config,
                    re.DOTALL
                )
                
                for ingress in ingress_blocks:
                    ingress_config = ingress.group(1)
                    
                    # Check if rule allows public access
                    if '0.0.0.0/0' in ingress_config:
                        # Extract port information
                        from_port_match = re.search(r'from_port\s*=\s*(\d+)', ingress_config)
                        to_port_match = re.search(r'to_port\s*=\s*(\d+)', ingress_config)
                        
                        if from_port_match and to_port_match:
                            from_port = int(from_port_match.group(1))
                            to_port = int(to_port_match.group(1))
                            
                            # Check port range against sensitive ports
                            for port, service in self.sensitive_ports.items():
                                if from_port <= port <= to_port:
                                    line_num = self._find_line_number(content, ingress_config)
                                    finding = SecurityFinding(
                                        self.rule_id,
                                        self.severity,
                                        f"Security group '{sg_name}' exposes sensitive {service} port ({port}) to the public",
                                        line_num
                                    )
                                    finding.add_suggestion(f"""
                                        Restrict access to {service} port {port}:
                                        ingress {{
                                            from_port   = {port}
                                            to_port     = {port}
                                            protocol    = "tcp"
                                            cidr_blocks = ["YOUR-TRUSTED-IP-RANGE"]  # Replace with specific IP range
                                        }}""")
                                    self.findings.append(finding)
        
        return self.findings

# Add this to src/rules/network_rules.py

class NetworkACLRule(SecurityRule):
    """
    Validates Network ACL configurations for security best practices.
    Checks for overly permissive rules and ensures proper rule ordering.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "NetworkACLValidation"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_network_acl"' in content:
            # Find all NACL blocks
            nacl_blocks = re.finditer(
                r'resource\s+"aws_network_acl"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for nacl_match in nacl_blocks:
                nacl_name = nacl_match.group(1)
                nacl_config = nacl_match.group(2)
                
                # Check for overly permissive ingress rules
                ingress_rules = re.finditer(
                    r'ingress\s*{([^}]+)}',
                    nacl_config,
                    re.DOTALL
                )
                
                for ingress in ingress_rules:
                    rule_config = ingress.group(1)
                    
                    # Check for "allow all" rules
                    if ('protocol\s*=\s*"-1"' in rule_config or 
                        'protocol\s*=\s*"all"' in rule_config) and \
                       '0.0.0.0/0' in rule_config:
                        
                        # Check rule number to ensure proper ordering
                        rule_number_match = re.search(r'rule_no\s*=\s*(\d+)', rule_config)
                        if rule_number_match:
                            rule_number = int(rule_number_match.group(1))
                            
                            if rule_number < 100:  # Early rule numbers are higher priority
                                line_num = self._find_line_number(content, rule_config)
                                finding = SecurityFinding(
                                    self.rule_id,
                                    self.severity,
                                    f"Network ACL '{nacl_name}' has an overly permissive rule (rule {rule_number}) that allows all traffic",
                                    line_num
                                )
                                finding.add_suggestion("""
                                    Implement more specific NACL rules:
                                    resource "aws_network_acl" "example" {
                                      vpc_id = aws_vpc.example.id
                                      
                                      ingress {
                                        protocol   = "tcp"
                                        rule_no    = 100
                                        action     = "allow"
                                        cidr_block = "10.0.0.0/16"  # Your VPC CIDR
                                        from_port  = 443
                                        to_port    = 443
                                      }
                                      
                                      # Add specific rules for each required port/protocol
                                      # Use higher rule numbers (100+) for allow rules
                                      # Use lower rule numbers for deny rules
                                    }""")
                                self.findings.append(finding)
                
                # Check for missing explicit deny rules
                if not re.search(r'rule_no\s*=\s*(\d+).*action\s*=\s*"deny"', nacl_config):
                    line_num = self._find_line_number(content, nacl_name)
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"Network ACL '{nacl_name}' is missing explicit deny rules",
                        line_num
                    )
                    finding.add_suggestion("""
                        Add explicit deny rules with low rule numbers:
                        ingress {
                          protocol   = "-1"
                          rule_no    = 32767
                          action     = "deny"
                          cidr_block = "0.0.0.0/0"
                          from_port  = 0
                          to_port    = 0
                        }""")
                    self.findings.append(finding)
        
        return self.findings