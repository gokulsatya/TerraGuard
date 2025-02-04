# src/rules/container_db_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class ECSSecurityRule(SecurityRule):
    """
    Checks security configurations for ECS (Elastic Container Service).
    Ensures containers follow security best practices and are properly isolated.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "ECSSecurityCheck"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        # Check ECS Task Definitions
        if 'resource "aws_ecs_task_definition"' in content:
            task_blocks = re.finditer(
                r'resource\s+"aws_ecs_task_definition"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for task in task_blocks:
                task_name = task.group(1)
                task_config = task.group(2)
                
                # Check for privileged containers
                if re.search(r'"privileged":\s*true', task_config):
                    finding = SecurityFinding(
                        "ECSPrivilegedContainer",
                        "CRITICAL",
                        f"ECS Task '{task_name}' contains privileged containers",
                        None
                    )
                    finding.add_suggestion("""
                        Avoid using privileged containers unless absolutely necessary:
                        resource "aws_ecs_task_definition" "example" {
                          container_definitions = jsonencode([
                            {
                              name = "app"
                              privileged = false  # Default should be false
                              # Use specific capabilities instead if needed
                            }
                          ])
                        }""")
                    self.findings.append(finding)
                
                # Check for container logging
                if not re.search(r'"logConfiguration":', task_config):
                    finding = SecurityFinding(
                        "ECSLoggingDisabled",
                        "MEDIUM",
                        f"ECS Task '{task_name}' does not have logging configured",
                        None
                    )
                    finding.add_suggestion("""
                        Enable container logging:
                        resource "aws_ecs_task_definition" "example" {
                          container_definitions = jsonencode([
                            {
                              name = "app"
                              logConfiguration = {
                                logDriver = "awslogs"
                                options = {
                                  "awslogs-group" = "/ecs/app-logs"
                                  "awslogs-region" = "us-west-2"
                                  "awslogs-stream-prefix" = "app"
                                }
                              }
                            }
                          ])
                        }""")
                    self.findings.append(finding)

        return self.findings

class EKSSecurityRule(SecurityRule):
    """
    Validates security settings for EKS (Elastic Kubernetes Service).
    Ensures clusters are properly secured and follow best practices.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "EKSSecurityCheck"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_eks_cluster"' in content:
            cluster_blocks = re.finditer(
                r'resource\s+"aws_eks_cluster"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for cluster in cluster_blocks:
                cluster_name = cluster.group(1)
                cluster_config = cluster.group(2)
                
                # Check for encryption configuration
                if not re.search(r'encryption_config\s*{', cluster_config):
                    finding = SecurityFinding(
                        "EKSEncryption",
                        self.severity,
                        f"EKS Cluster '{cluster_name}' does not have encryption configured",
                        None
                    )
                    finding.add_suggestion("""
                        Enable encryption for EKS secrets:
                        resource "aws_eks_cluster" "example" {
                          # ... other configuration ...
                          encryption_config {
                            provider {
                              key_arn = aws_kms_key.eks.arn
                            }
                            resources = ["secrets"]
                          }
                        }""")
                    self.findings.append(finding)
                
                # Check for public access
                if re.search(r'endpoint_public_access\s*=\s*true', cluster_config):
                    if not re.search(r'public_access_cidrs\s*=\s*\[', cluster_config):
                        finding = SecurityFinding(
                            "EKSPublicAccess",
                            self.severity,
                            f"EKS Cluster '{cluster_name}' has unrestricted public access",
                            None
                        )
                        finding.add_suggestion("""
                            Restrict public access to specific IP ranges:
                            resource "aws_eks_cluster" "example" {
                              vpc_config {
                                endpoint_public_access = true
                                public_access_cidrs   = ["YOUR-IP/32"]
                              }
                            }
                            
                            # Or disable public access entirely:
                            vpc_config {
                              endpoint_public_access = false
                              endpoint_private_access = true
                            }""")
                        self.findings.append(finding)

        return self.findings

class DynamoDBSecurityRule(SecurityRule):
    """
    Checks security configurations for DynamoDB tables.
    Ensures proper encryption and access controls are in place.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "DynamoDBSecurity"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_dynamodb_table"' in content:
            table_blocks = re.finditer(
                r'resource\s+"aws_dynamodb_table"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for table in table_blocks:
                table_name = table.group(1)
                table_config = table.group(2)
                
                # Check for server-side encryption with CMK
                if not re.search(r'server_side_encryption\s*{[^}]*kms_key_arn', table_config):
                    finding = SecurityFinding(
                        "DynamoDBEncryption",
                        self.severity,
                        f"DynamoDB table '{table_name}' is not using customer-managed KMS key",
                        None
                    )
                    finding.add_suggestion("""
                        Enable encryption with a customer-managed KMS key:
                        resource "aws_dynamodb_table" "example" {
                          name = "example-table"
                          # ... other configuration ...
                          
                          server_side_encryption {
                            enabled     = true
                            kms_key_arn = aws_kms_key.dynamodb.arn
                          }
                        }
                        
                        resource "aws_kms_key" "dynamodb" {
                          description             = "KMS key for DynamoDB encryption"
                          deletion_window_in_days = 7
                          enable_key_rotation     = true
                        }""")
                    self.findings.append(finding)
                
                # Check for point-in-time recovery
                if not re.search(r'point_in_time_recovery\s*{[^}]*enabled\s*=\s*true', table_config):
                    finding = SecurityFinding(
                        "DynamoDBRecovery",
                        "MEDIUM",
                        f"DynamoDB table '{table_name}' does not have point-in-time recovery enabled",
                        None
                    )
                    finding.add_suggestion("""
                        Enable point-in-time recovery for data protection:
                        resource "aws_dynamodb_table" "example" {
                          # ... other configuration ...
                          
                          point_in_time_recovery {
                            enabled = true
                          }
                        }""")
                    self.findings.append(finding)

        return self.findings