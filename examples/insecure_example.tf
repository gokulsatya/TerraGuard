# examples/insecure_example.tf
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # Security issue!
}