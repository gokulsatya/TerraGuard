# examples/container_db_example.tf

# Insecure ECS Task Definition
resource "aws_ecs_task_definition" "insecure_task" {
  family = "service"
  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "app:latest"
      privileged = true  # Security issue
      # Missing logging configuration
    }
  ])
}

# Insecure EKS Cluster
resource "aws_eks_cluster" "insecure_cluster" {
  name     = "example"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    endpoint_public_access = true  # Security issue
    # Missing public_access_cidrs restriction
  }
  # Missing encryption_config
}

# Insecure DynamoDB Table
resource "aws_dynamodb_table" "insecure_table" {
  name           = "example-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  
  attribute {
    name = "id"
    type = "S"
  }
  # Missing server_side_encryption with CMK
  # Missing point_in_time_recovery
}