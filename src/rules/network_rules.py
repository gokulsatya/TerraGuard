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