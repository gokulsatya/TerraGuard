# examples/cloud_services_example.tf

# Insecure Elasticsearch configuration
resource "aws_elasticsearch_domain" "insecure_es" {
  domain_name = "example-domain"
  
  # Missing encryption at rest
  # Missing node-to-node encryption
}

# Insecure Lambda configuration
resource "aws_lambda_function" "insecure_lambda" {
  filename      = "lambda.zip"
  function_name = "example_lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "exports.test"
  runtime       = "nodejs14.x"

  environment {
    variables = {
      SENSITIVE_DATA = "my-secret"  # Unencrypted environment variable
    }
  }
  
  # Missing VPC configuration
}