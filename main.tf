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

# S3 Bucket for Login Page
resource "aws_s3_bucket" "login_page" {
  bucket = "${var.project_name}-login-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-login-${var.environment}"
  }
}

resource "aws_s3_bucket_public_access_block" "login_page" {
  bucket = aws_s3_bucket.login_page.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "login_page" {
  bucket = aws_s3_bucket.login_page.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "login_page" {
  bucket = aws_s3_bucket.login_page.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudFront Origin Access Identity
resource "aws_cloudfront_origin_access_identity" "login_page" {
  count   = var.enable_cloudfront ? 1 : 0
  comment = "OAI for ${var.project_name} login page"
}

# S3 Bucket Policy for CloudFront
resource "aws_s3_bucket_policy" "login_page" {
  bucket = aws_s3_bucket.login_page.id

  policy = var.enable_cloudfront ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOAI"
        Effect = "Allow"
        Principal = {
          AWS = aws_cloudfront_origin_access_identity.login_page[0].iam_arn
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.login_page.arn}/*"
      }
    ]
  }) : jsonencode({
    Version = "2012-10-17"
    Statement = []
  })
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "login_page" {
  count               = var.enable_cloudfront ? 1 : 0
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    domain_name = aws_s3_bucket.login_page.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.login_page.id}"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.login_page[0].cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.login_page.id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${var.project_name}-login-${var.environment}"
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution" {
  name = "${var.project_name}-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-lambda-${var.environment}"
  }
}

resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "dynamodb-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem"
        ]
        Resource = [
          aws_dynamodb_table.users.arn,
          "${aws_dynamodb_table.users.arn}/index/*",
          aws_dynamodb_table.roles.arn,
          "${aws_dynamodb_table.roles.arn}/index/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_ssm" {
  name = "ssm-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/${var.environment}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "saml_dependencies" {
  filename            = data.archive_file.lambda_layer.output_path
  layer_name          = "${var.project_name}-dependencies-${var.environment}"
  compatible_runtimes = ["python3.11", "python3.12"]
  source_code_hash    = data.archive_file.lambda_layer.output_base64sha256

  description = "SAML and cryptography dependencies"
}

# Lambda Function for SAML Processing
resource "aws_lambda_function" "saml_processor" {
  filename         = data.archive_file.lambda_function.output_path
  function_name    = "${var.project_name}-processor-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.lambda_function.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 512

  layers = [aws_lambda_layer_version.saml_dependencies.arn]

  environment {
    variables = {
      USERS_TABLE           = aws_dynamodb_table.users.name
      ROLES_TABLE           = aws_dynamodb_table.roles.name
      IDP_ENTITY_ID         = var.idp_entity_id
      IDP_BASE_URL          = var.idp_base_url
      SESSION_DURATION      = var.session_duration_seconds
      SSM_PARAMETER_PREFIX  = "/${var.project_name}/${var.environment}"
      ALLOWED_AWS_ACCOUNTS  = jsonencode(var.allowed_aws_accounts)
    }
  }

  tags = {
    Name = "${var.project_name}-processor-${var.environment}"
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.saml_processor.function_name}"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-lambda-logs-${var.environment}"
  }
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "saml" {
  name          = "${var.project_name}-api-${var.environment}"
  protocol_type = "HTTP"
  description   = "SAML IdP API for AWS Console SSO"

  cors_configuration {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization"]
    max_age       = 300
  }

  tags = {
    Name = "${var.project_name}-api-${var.environment}"
  }
}

# Lambda Integration
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.saml.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.saml_processor.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

# API Routes
resource "aws_apigatewayv2_route" "metadata" {
  api_id    = aws_apigatewayv2_api.saml.id
  route_key = "GET /metadata"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "sso" {
  api_id    = aws_apigatewayv2_api.saml.id
  route_key = "POST /sso"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "login" {
  api_id    = aws_apigatewayv2_api.saml.id
  route_key = "POST /login"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "acs" {
  api_id    = aws_apigatewayv2_api.saml.id
  route_key = "POST /acs"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# API Stage
resource "aws_apigatewayv2_stage" "saml" {
  api_id      = aws_apigatewayv2_api.saml.id
  name        = var.environment
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }

  tags = {
    Name = "${var.project_name}-api-stage-${var.environment}"
  }
}

# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_logs" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = 7

  tags = {
    Name = "${var.project_name}-api-logs-${var.environment}"
  }
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.saml_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.saml.execution_arn}/*/*"
}

# SSM Parameters for SAML Configuration
resource "aws_ssm_parameter" "saml_private_key" {
  name        = "/${var.project_name}/${var.environment}/saml/private_key"
  description = "SAML signing private key (RSA)"
  type        = "SecureString"
  value       = "PLACEHOLDER_REPLACE_WITH_ACTUAL_KEY"

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "${var.project_name}-saml-private-key-${var.environment}"
  }
}

resource "aws_ssm_parameter" "saml_certificate" {
  name        = "/${var.project_name}/${var.environment}/saml/certificate"
  description = "SAML signing certificate (X.509)"
  type        = "String"
  value       = "PLACEHOLDER_REPLACE_WITH_ACTUAL_CERT"

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "${var.project_name}-saml-certificate-${var.environment}"
  }
}

# Data Sources
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "archive_file" "lambda_function" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/function"
  output_path = "${path.module}/.terraform/lambda_function.zip"
}

data "archive_file" "lambda_layer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/layer"
  output_path = "${path.module}/.terraform/lambda_layer.zip"
}
