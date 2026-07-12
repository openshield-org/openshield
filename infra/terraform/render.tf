resource "render_postgres" "db" {
  name    = "openshield-db"
  plan    = var.render_postgres_plan
  region  = var.render_region
  version = "16"

  database_name = "openshield"
  database_user = "openshield"
}

resource "render_env_group" "api_secrets" {
  name = "openshield-api-secrets"

  env_vars = {
    JWT_SECRET            = { value = var.jwt_secret }
    ANTHROPIC_API_KEY     = { value = var.anthropic_api_key }
    GROQ_API_KEY          = { value = var.groq_api_key }
    GEMINI_API_KEY        = { value = var.gemini_api_key }
    NVD_API_KEY           = { value = var.nvd_api_key }
    SENTRY_DSN            = { value = var.sentry_dsn }
    AZURE_SUBSCRIPTION_ID = { value = var.azure_subscription_id }
    AZURE_CLIENT_ID       = { value = var.azure_client_id }
    AZURE_TENANT_ID       = { value = var.azure_tenant_id }
  }
}

resource "render_web_service" "api" {
  name   = "openshield-api"
  plan   = var.render_web_service_plan
  region = var.render_region

  runtime_source = {
    docker = {
      repo_url        = "https://github.com/openshield-org/openshield"
      branch          = "main"
      dockerfile_path = "Dockerfile"
    }
  }

  start_command = "./startup.sh"

  env_vars = {
    DATABASE_URL    = { value = var.database_url }
    ALLOWED_ORIGINS = { value = var.allowed_origins }
    OPENSHIELD_ENV  = { value = "production" }
    RENDER          = { value = "true" }
  }
}

resource "render_env_group_link" "api_secrets_link" {
  env_group_id = render_env_group.api_secrets.id
  service_ids  = [render_web_service.api.id]
}
