variable "db_password" {
  description = "The database password"
  default     = "supersecret123"  # Failure: hardcoded secret (assuming your checks catch this)
}
