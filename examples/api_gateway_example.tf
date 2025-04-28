# examples/api_gateway_example.tf

# Insecure API Gateway configuration
resource "aws_api_gateway_method" "insecure_method" {
  rest_api_id   = aws_api_gateway_rest_api.example.id
  resource_id   = aws_api_gateway_resource.example.id
  http_method   = "POST"
  authorization = "NONE"  # This will trigger our security check
}

# Secure API Gateway configuration
resource "aws_api_gateway_method" "secure_method" {
  rest_api_id   = aws_api_gateway_rest_api.example.id
  resource_id   = aws_api_gateway_resource.example.id
  http_method   = "GET"
  authorization = "AWS_IAM"
  api_key_required = true
}    
