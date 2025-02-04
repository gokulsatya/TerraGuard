# src/rules/api_gateway_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class APIGatewayAuthorizationRule(SecurityRule):
    """
    Checks if API Gateway endpoints have proper authorization configured.
    Missing authorization could allow unauthorized access to your APIs.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "APIGatewayNoAuth"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Look for API Gateway method resources
        if 'resource "aws_api_gateway_method"' in content:
            # Find all API Gateway method blocks using regex
            method_blocks = re.finditer(
                r'resource\s+"aws_api_gateway_method"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for method in method_blocks:
                method_name = method.group(1)
                method_config = method.group(2)
                
                # Check for authorization issues
                self._check_authorization(method_name, method_config)
                self._check_api_key_requirement(method_name, method_config)
        
        return self.findings

    def _check_authorization(self, method_name: str, method_config: str):
        """Check if the method has proper authorization configured."""
        if re.search(r'authorization\s*=\s*"NONE"', method_config):
            finding = SecurityFinding(
                self.rule_id,
                self.severity,
                f"API Gateway method '{method_name}' has no authorization configured",
                None  # Line number will be added by the base class
            )
            finding.add_suggestion("""
                Configure appropriate authorization:
                resource "aws_api_gateway_method" "example" {
                  rest_api_id   = aws_api_gateway_rest_api.example.id
                  resource_id   = aws_api_gateway_resource.example.id
                  http_method   = "GET"
                  authorization = "AWS_IAM"  # Use appropriate auth type
                  
                  # For Cognito:
                  # authorization = "COGNITO_USER_POOLS"
                  # authorizer_id = aws_api_gateway_authorizer.cognito.id
                  
                  # For Custom authorizer:
                  # authorization = "CUSTOM"
                  # authorizer_id = aws_api_gateway_authorizer.custom.id
                }""")
            self.findings.append(finding)

    def _check_api_key_requirement(self, method_name: str, method_config: str):
        """Check if the method requires an API key for sensitive operations."""
        if 'POST' in method_config or 'PUT' in method_config or 'DELETE' in method_config:
            if not re.search(r'api_key_required\s*=\s*true', method_config):
                finding = SecurityFinding(
                    "APIGatewayNoApiKey",
                    "MEDIUM",
                    f"API Gateway method '{method_name}' does not require an API key for write operation",
                    None
                )
                finding.add_suggestion("""
                    Require API key for write operations:
                    resource "aws_api_gateway_method" "example" {
                      # ... other configuration ...
                      api_key_required = true
                    }
                    
                    # Don't forget to create and configure the API key:
                    resource "aws_api_gateway_api_key" "example" {
                      name = "my-api-key"
                    }""")
                self.findings.append(finding)