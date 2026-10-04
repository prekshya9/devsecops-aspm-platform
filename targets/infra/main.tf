provider "aws" {
  region = "eu-west-2"
}

# Flaw 1: S3 bucket holding personal customer records
resource "aws_s3_bucket" "customer_data" {
  bucket = "enterprise-customer-utility-records-backup"
}
# Fix: Enforce strict private access & block all public access
resource "aws_s3_bucket_public_access_block" "customer_data_block" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Flaw 3: Unencrypted storage volume containing customer DB data (Violates ISO 27001 A.8.24)
resource "aws_ebs_volume" "database_disk" {
  availability_zone = "eu-west-2a"
  size              = 50
  encrypted         = true
}