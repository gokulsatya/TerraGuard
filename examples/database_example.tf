# examples/database_example.tf

# Example 1: Insecure RDS Instance (multiple issues)
resource "aws_db_instance" "insecure_db" {
    identifier = "production-db"
    engine     = "mysql"
    
    # Security Issue 1: Publicly accessible
    publicly_accessible = true
    
    # Security Issue 2: No encryption
    # Missing storage_encrypted = true
    
    # Security Issue 3: Backups disabled
    backup_retention_period = 0
}

# Example 2: Secure RDS Instance (following best practices)
resource "aws_db_instance" "secure_db" {
    identifier = "production-db-secure"
    engine     = "mysql"
    
    # Private access only
    publicly_accessible = false
    db_subnet_group_name = aws_db_subnet_group.private.name
    
    # Enable encryption
    storage_encrypted = true
    kms_key_id = aws_kms_key.database.arn
    
    # Configure backups
    backup_retention_period = 7
    backup_window = "03:00-04:00"
}