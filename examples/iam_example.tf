# examples/iam_example.tf

# Example 1: Overly permissive admin policy
resource "aws_iam_policy" "admin_policy" {
    name = "full-admin-access"
    description = "Grants full administrative access"
    
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = "*"  # This is dangerous!
                Resource = "*"  # This is also dangerous!
            }
        ]
    })
}

# Example 2: Hard-coded credentials (never do this!)
provider "aws" {
    region = "us-west-2"
    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  # This is dangerous!
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # This is dangerous!
}

# Example 3: Overly permissive role trust relationship
resource "aws_iam_role" "example_role" {
    name = "example-role"
    
    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Principal = {
                    AWS = "*"  # This is dangerous!
                }
                Action = "sts:AssumeRole"
            }
        ]
    })
}

# Example 4: A better-configured IAM policy
resource "aws_iam_policy" "better_policy" {
    name = "specific-s3-access"
    description = "Grants specific S3 bucket access"
    
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "s3:GetObject",
                    "s3:ListBucket"
                ]
                Resource = [
                    "arn:aws:s3:::specific-bucket",
                    "arn:aws:s3:::specific-bucket/*"
                ]
            }
        ]
    })
}