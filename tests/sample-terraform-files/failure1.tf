resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-bucket"
  acl    = "public-read"   # Warning: publicly readable bucket
  tags = {
    Environment = "prod"
  }
}
