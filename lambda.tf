# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "saml_dependencies" {
  filename            = data.archive_file.lambda_layer.output_path
  layer_name          = "${local.project_name}-dependencies-${local.environment}"
  compatible_runtimes = ["python3.13"]
  source_code_hash    = data.archive_file.lambda_layer.output_base64sha256

  description = "SAML and cryptography dependencies"
}

# Lambda Function for SAML Processing
resource "aws_lambda_function" "saml_processor" {
  filename         = data.archive_file.saml_processor_function.output_path
  function_name    = "${local.project_name}-processor-${local.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.saml_processor_function.output_base64sha256
  runtime          = "python3.13"
  timeout          = 30
  memory_size      = 512

  environment {
    variables = {
      USERS_TABLE          = aws_dynamodb_table.users.name
      ROLES_TABLE          = aws_dynamodb_table.roles.name
      IDP_ENTITY_ID        = local.idp_entity_id
      IDP_BASE_URL         = var.idp_base_url
      SESSION_DURATION     = var.session_duration_seconds
      SSM_PARAMETER_PREFIX = "/${local.project_name}/${local.environment}"
      ALLOWED_AWS_ACCOUNTS = jsonencode(var.allowed_aws_accounts)
      SAML_PROVIDER_NAME   = var.saml_provider_name
    }
  }

  tags = {
    Name = "${local.project_name}-processor-${local.environment}"
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

# Lambda Function for User and Role Management
resource "aws_lambda_function" "manage_users_roles" {
  filename         = data.archive_file.manage_users_roles_function.output_path
  function_name    = "${local.project_name}-manage-users-roles-${local.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.manage_users_roles_function.output_base64sha256
  runtime          = "python3.13"
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      USERS_TABLE = aws_dynamodb_table.users.name
      ROLES_TABLE = aws_dynamodb_table.roles.name
    }
  }

  tags = {
    Name = "${local.project_name}-manage-users-roles-${local.environment}"
  }
}
