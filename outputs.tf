output "api_gateway_url" {
  description = "API Gateway endpoint URL for SAML endpoints"
  value       = aws_apigatewayv2_stage.saml.invoke_url
}

output "login_page_url" {
  description = "URL to access the login page (CloudFront recommended for HTTPS access)"
  value       = var.enable_cloudfront ? "https://${aws_cloudfront_distribution.login_page[0].domain_name}" : "Note: Direct S3 access without CloudFront requires additional configuration for HTTPS. Enable CloudFront or configure S3 website hosting."
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (if enabled)"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.login_page[0].id : null
}

output "s3_bucket_name" {
  description = "S3 bucket name for login page"
  value       = aws_s3_bucket.login_page.id
}

output "dynamodb_users_table" {
  description = "DynamoDB table name for users"
  value       = aws_dynamodb_table.users.name
}

output "dynamodb_roles_table" {
  description = "DynamoDB table name for roles"
  value       = aws_dynamodb_table.roles.name
}

output "saml_metadata_url" {
  description = "SAML metadata endpoint URL"
  value       = "${aws_apigatewayv2_stage.saml.invoke_url}/metadata"
}

output "saml_sso_url" {
  description = "SAML SSO endpoint URL"
  value       = "${aws_apigatewayv2_stage.saml.invoke_url}/sso"
}

output "saml_entity_id" {
  description = "SAML Identity Provider Entity ID"
  value       = local.idp_entity_id
}

output "manage_users_roles_lambda_arn" {
  description = "ARN of the Lambda function for managing users and roles"
  value       = aws_lambda_function.manage_users_roles.arn
}

output "manage_users_roles_lambda_name" {
  description = "Name of the Lambda function for managing users and roles"
  value       = aws_lambda_function.manage_users_roles.function_name
}
