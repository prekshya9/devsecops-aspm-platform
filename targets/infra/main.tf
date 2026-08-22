provider "aws" {
  region = "eu-west-2"
}

# Flaw 1: S3 bucket holding personal customer records
resource "aws_s3_bucket" "customer_data" {
  bucket = "enterprise-customer-utility-records-backup"
}

# Flaw 2: Public read access enabled (Violates GDPR Art. 32 & ISO 27001 A.8.20)
resource "aws_s3_bucket_acl" "insecure_acl" {
  bucket = aws_s3_bucket.customer_data.id
  acl    = "public-read"
}

# Flaw 3: Unencrypted storage volume containing customer DB data (Violates ISO 27001 A.8.24)
resource "aws_ebs_volume" "database_disk" {
  availability_zone = "eu-west-2a"
  size              = 50
  encrypted         = false
}