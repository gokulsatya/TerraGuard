# src/rules/base_rules.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import re

class SecurityFinding:
    """Represents a security issue found in Terraform code"""
    
    def __init__(self, rule_id: str, severity: str, message: str, line_number: int = None):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.line_number = line_number
        self.suggested_fix = None

    def add_suggestion(self, fix: str):
        """Adds a suggested fix for the security issue"""
        self.suggested_fix = fix

    def to_dict(self) -> Dict[str, Any]:
        """Converts the finding to a dictionary format"""
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'message': self.message,
            'line_number': self.line_number,
            'suggested_fix': self.suggested_fix
        }

class SecurityRule(ABC):
    """Base class for all security rules"""
    
    def __init__(self):
        self.rule_id = self.__class__.__name__
        self.severity = "HIGH"
        self.findings: List[SecurityFinding] = []

    @abstractmethod
    def analyze(self, content: str) -> List[SecurityFinding]:
        """Analyzes Terraform content and returns a list of findings"""
        pass

    def _find_line_number(self, content: str, pattern: str) -> int:
        """Helper method to find the line number where a pattern appears"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return None

class RulesEngine:
    """Main engine that applies security rules to Terraform content"""
    
    def __init__(self):
        self.rules: List[SecurityRule] = []

    def register_rule(self, rule: SecurityRule):
        """Adds a new rule to the engine"""
        self.rules.append(rule)

    def analyze(self, content: str) -> List[Dict[str, Any]]:
        """
        Analyzes Terraform content using all registered rules
        
        Args:
            content (str): Terraform configuration content
            
        Returns:
            List[Dict]: List of findings from all rules
        """
        all_findings = []
        for rule in self.rules:
            findings = rule.analyze(content)
            all_findings.extend([f.to_dict() for f in findings])
        return all_findings