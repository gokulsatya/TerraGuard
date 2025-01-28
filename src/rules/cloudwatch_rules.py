# src/rules/cloudwatch_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class CloudWatchLogRetentionRule(SecurityRule):
    """
    Ensures that CloudWatch log groups have appropriate retention periods set.
    Log retention is crucial for security analysis, compliance requirements,
    and incident investigation.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "CloudWatchRetention"
        self.severity = "MEDIUM"
        self.min_retention_days = 30  # Minimum recommended retention period

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_cloudwatch_log_group"' in content:
            # Find all log group definitions
            log_groups = re.finditer(
                r'resource\s+"aws_cloudwatch_log_group"\s+"([^"]+)"\s+{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for match in log_groups:
                group_name = match.group(1)
                group_config = match.group(2)
                
                # Check retention period
                retention_match = re.search(
                    r'retention_in_days\s*=\s*(\d+)',
                    group_config
                )
                
                if not retention_match or \
                   int(retention_match.group(1)) < self.min_retention_days:
                    line_num = self._find_line_number(content, group_name)
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"CloudWatch Log Group '{group_name}' has insufficient retention period",
                        line_num
                    )
                    finding.add_suggestion(f"""
                        Configure appropriate log retention (minimum {self.min_retention_days} days recommended):
                        resource "aws_cloudwatch_log_group" "example" {{
                          name              = "/aws/example/logs"
                          retention_in_days = {self.min_retention_days}
                          
                          # Consider adding KMS encryption
                          kms_key_id = aws_kms_key.log_encryption.arn
                        }}""")
                    self.findings.append(finding)
        
        return self.findings

class CloudWatchLogEncryptionRule(SecurityRule):
    """
    Verifies that CloudWatch log groups are encrypted with KMS keys.
    Log encryption protects sensitive information that might be present
    in application logs, audit trails, and system logs.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "CloudWatchEncryption"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_cloudwatch_log_group"' in content:
            # Find log groups without KMS encryption
            log_groups = re.finditer(
                r'resource\s+"aws_cloudwatch_log_group"\s+"([^"]+)"\s+{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for match in log_groups:
                group_name = match.group(1)
                group_config = match.group(2)
                
                if 'kms_key_id' not in group_config:
                    line_num = self._find_line_number(content, group_name)
                    finding = SecurityFinding(
                        self.rule_id,
                        self.severity,
                        f"CloudWatch Log Group '{group_name}' is not encrypted with KMS",
                        line_num
                    )
                    finding.add_suggestion("""
                        Enable KMS encryption for CloudWatch logs:
                        # First, create a KMS key for log encryption
                        resource "aws_kms_key" "log_encryption" {
                          description         = "KMS key for CloudWatch log encryption"
                          enable_key_rotation = true
                          
                          policy = jsonencode({
                            Version = "2012-10-17"
                            Statement = [
                              {
                                Sid    = "Enable CloudWatch Logs"
                                Effect = "Allow"
                                Principal = {
                                  Service = "logs.amazonaws.com"
                                }
                                Action = [
                                  "kms:Encrypt*",
                                  "kms:Decrypt*",
                                  "kms:ReEncrypt*",
                                  "kms:GenerateDataKey*",
                                  "kms:Describe*"
                                ]
                                Resource = "*"
                              }
                            ]
                          })
                        }
                        
                        # Then use it in your log group
                        resource "aws_cloudwatch_log_group" "example" {
                          name       = "/aws/example/logs"
                          kms_key_id = aws_kms_key.log_encryption.arn
                        }""")
                    self.findings.append(finding)
        
        return self.findings

class CloudWatchLogMetricFilterRule(SecurityRule):
    """
    Checks for the presence of metric filters that monitor security-critical events.
    Metric filters help detect and alert on important security events like
    unauthorized API calls, network ACL changes, or root account usage.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "CloudWatchMetricFilters"
        self.severity = "MEDIUM"
        
        # Define critical security events that should be monitored
        self.critical_patterns = [
            ("unauthorized-api-calls", "$.errorCode = *UnauthorizedOperation"),
            ("root-account-usage", "$.userIdentity.type = Root"),
            ("iam-changes", "$.eventName = DeleteUserPolicy"),
            ("network-changes", "$.eventName = CreateNetworkAcl"),
            ("security-group-changes", "$.eventName = AuthorizeSecurityGroupIngress")
        ]

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Check for metric filter definitions
        if 'resource "aws_cloudwatch_log_metric_filter"' in content:
            existing_patterns = {
                pattern: False for name, pattern in self.critical_patterns
            }
            
            # Find all metric filters
            metric_filters = re.finditer(
                r'resource\s+"aws_cloudwatch_log_metric_filter"\s+"([^"]+)"\s+{([^}]+)}',
                content,
                re.DOTALL
            )
            
            # Check which critical patterns are covered
            for match in metric_filters:
                filter_config = match.group(2)
                for name, pattern in self.critical_patterns:
                    if pattern in filter_config:
                        existing_patterns[pattern] = True
            
            # Report missing critical metric filters
            missing_patterns = [
                name for name, pattern in self.critical_patterns
                if not existing_patterns[pattern]
            ]
            
            if missing_patterns:
                finding = SecurityFinding(
                    self.rule_id,
                    self.severity,
                    "Missing critical CloudWatch metric filters for: " + 
                    ", ".join(missing_patterns),
                    None
                )
                finding.add_suggestion("""
                    Add metric filters for critical security events:
                    resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
                      name           = "unauthorized-api-calls"
                      pattern        = "$.errorCode = *UnauthorizedOperation"
                      log_group_name = aws_cloudwatch_log_group.example.name

                      metric_transformation {
                        name          = "UnauthorizedAPICalls"
                        namespace     = "SecurityMetrics"
                        value        = 1
                        default_value = 0
                      }
                    }
                    
                    # Also create corresponding alarms
                    resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
                      alarm_name          = "unauthorized-api-calls"
                      comparison_operator = "GreaterThanThreshold"
                      evaluation_periods  = 1
                      metric_name        = "UnauthorizedAPICalls"
                      namespace          = "SecurityMetrics"
                      period             = 300
                      statistic          = "Sum"
                      threshold          = 1
                      alarm_description  = "Unauthorized API calls detected"
                      alarm_actions      = [aws_sns_topic.security_alerts.arn]
                    }""")
                self.findings.append(finding)
        
        return self.findings