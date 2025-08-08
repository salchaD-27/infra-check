resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-private-bucket"
  acl    = "private"       # Good: not public
  tags = {
    Environment = "dev"
  }
}

variable "instance_count" {
  type    = number
  default = 3
}
