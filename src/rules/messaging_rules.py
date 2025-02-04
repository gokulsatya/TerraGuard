# src/rules/messaging_rules.py

from .base_rules import SecurityRule, SecurityFinding
import re

class SNSTopicSecurityRule(SecurityRule):
    """
    Validates security configurations for SNS topics.
    Checks encryption settings, access policies, and cross-account permissions.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "SNSTopicSecurity"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_sns_topic"' in content:
            topic_blocks = re.finditer(
                r'resource\s+"aws_sns_topic"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for topic in topic_blocks:
                topic_name = topic.group(1)
                topic_config = topic.group(2)
                
                # Check for KMS encryption
                if not re.search(r'kms_master_key_id\s*=', topic_config):
                    finding = SecurityFinding(
                        "SNSEncryption",
                        self.severity,
                        f"SNS Topic '{topic_name}' is not using KMS encryption",
                        None
                    )
                    finding.add_suggestion("""
                        Enable KMS encryption for SNS topic:
                        resource "aws_sns_topic" "example" {
                          name = "secure-topic"
                          kms_master_key_id = aws_kms_key.sns.id
                        }
                        
                        resource "aws_kms_key" "sns" {
                          description = "KMS key for SNS topic encryption"
                          enable_key_rotation = true
                          policy = jsonencode({
                            Version = "2012-10-17"
                            Statement = [
                              {
                                Sid = "Enable SNS Encryption"
                                Effect = "Allow"
                                Principal = {
                                  Service = "sns.amazonaws.com"
                                }
                                Action = [
                                  "kms:GenerateDataKey*",
                                  "kms:Decrypt"
                                ]
                                Resource = "*"
                              }
                            ]
                          })
                        }""")
                    self.findings.append(finding)

class SQSQueueSecurityRule(SecurityRule):
    """
    Validates security configurations for SQS queues.
    Checks encryption, dead-letter queues, and access policies.
    """
    
    def __init__(self):
        super().__init__()
        self.rule_id = "SQSQueueSecurity"
        self.severity = "HIGH"

    def analyze(self, content: str) -> list:
        self.findings = []
        
        if 'resource "aws_sqs_queue"' in content:
            queue_blocks = re.finditer(
                r'resource\s+"aws_sqs_queue"\s+"([^"]+)"\s*{([^}]+)}',
                content,
                re.DOTALL
            )
            
            for queue in queue_blocks:
                queue_name = queue.group(1)
                queue_config = queue.group(2)
                
                # Check for KMS encryption
                if not re.search(r'kms_master_key_id\s*=', queue_config):
                    finding = SecurityFinding(
                        "SQSEncryption",
                        self.severity,
                        f"SQS Queue '{queue_name}' is not using KMS encryption",
                        None
                    )
                    finding.add_suggestion("""
                        Enable KMS encryption for SQS queue:
                        resource "aws_sqs_queue" "example" {
                          name = "secure-queue"
                          kms_master_key_id = aws_kms_key.sqs.id
                          
                          # Consider adding a dead-letter queue
                          redrive_policy = jsonencode({
                            deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
                            maxReceiveCount     = 4
                          })
                        }""")
                    self.findings.append(finding)
                
                # Check for dead-letter queue
                if not re.search(r'redrive_policy\s*=', queue_config):
                    finding = SecurityFinding(
                        "SQSDeadLetter",
                        "MEDIUM",
                        f"SQS Queue '{queue_name}' does not have a dead-letter queue configured",
                        None
                    )
                    finding.add_suggestion("""
                        Configure a dead-letter queue:
                        resource "aws_sqs_queue" "dead_letter" {
                          name = "dead-letter-queue"
                          # Add appropriate encryption and retention settings
                        }
                        
                        resource "aws_sqs_queue" "main" {
                          name = "main-queue"
                          redrive_policy = jsonencode({
                            deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
                            maxReceiveCount     = 4
                          })
                        }""")
                    self.findings.append(finding)