# DynamoDB Tables
resource "aws_dynamodb_table" "users" {
  name           = "${var.project_name}-users-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "username"

  attribute {
    name = "username"
    type = "S"
  }

  attribute {
    name = "email"
    type = "S"
  }

  global_secondary_index {
    name            = "EmailIndex"
    hash_key        = "email"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-users-${var.environment}"
  }
}

resource "aws_dynamodb_table" "roles" {
  name           = "${var.project_name}-roles-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "username"
  range_key      = "role_arn"

  attribute {
    name = "username"
    type = "S"
  }

  attribute {
    name = "role_arn"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-roles-${var.environment}"
  }
}
