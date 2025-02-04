# tests/test_messaging_rules.py

import unittest
from src.rules.messaging_rules import SNSTopicSecurityRule, SQSQueueSecurityRule

class TestMessagingSecurityRules(unittest.TestCase):
    def setUp(self):
        self.sns_rule = SNSTopicSecurityRule()
        self.sqs_rule = SQSQueueSecurityRule()
    
    def test_sns_encryption_detection(self):
        """Test detection of unencrypted SNS topics"""
        terraform_content = '''
        resource "aws_sns_topic" "unencrypted" {
            name = "my-topic"
            # Missing encryption configuration
        }
        '''
        
        findings = self.sns_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 1)
        self.assertTrue(
            any("not using KMS encryption" in finding.message for finding in findings)
        )
    
    def test_sqs_security_configuration(self):
        """Test detection of multiple SQS security issues"""
        terraform_content = '''
        resource "aws_sqs_queue" "insecure" {
            name = "my-queue"
            # Missing encryption and DLQ
        }
        '''
        
        findings = self.sqs_rule.analyze(terraform_content)
        self.assertEqual(len(findings), 2)  # Should find missing encryption and DLQ
        messages = [f.message for f in findings]
        self.assertTrue(any("not using KMS encryption" in msg for msg in messages))
        self.assertTrue(any("dead-letter queue" in msg for msg in messages))

if __name__ == '__main__':
    unittest.main()