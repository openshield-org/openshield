variable "render_api_key" {
  description = "Render API key. Create at https://dashboard.render.com/u/settings#api-keys"
  type        = string
  sensitive   = true
}

variable "render_owner_id" {
  description = "Render owner (user or team) ID that owns the managed resources"
  type        = string
  sensitive   = true
}

variable "vercel_api_token" {
  description = "Vercel API token. Create at https://vercel.com/account/tokens"
  type        = string
  sensitive   = true
}

variable "vercel_team" {
  description = "Vercel team slug or ID that owns the managed projects"
  type        = string
  default     = null
}

variable "database_url" {
  description = "Full Postgres connection string for the API service (sourced from the render_postgres resource's connection_info in normal use; declared as a variable here since we are not applying yet)"
  type        = string
  sensitive   = true
  default     = null
}

variable "jwt_secret" {
  description = "JWT signing secret for the API service — must match between Render and any GitHub Actions secrets that also need it"
  type        = string
  sensitive   = true
  default     = null
}

variable "allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for the API service"
  type        = string
  default     = null
}

variable "anthropic_api_key" {
  description = "Anthropic API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "groq_api_key" {
  description = "Groq API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "gemini_api_key" {
  description = "Gemini API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "nvd_api_key" {
  description = "NVD API key for CVE enrichment (optional, raises the NVD rate limit)"
  type        = string
  sensitive   = true
  default     = null
}

variable "sentry_dsn" {
  description = "Sentry DSN for error tracking (optional)"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_subscription_id" {
  description = "Azure subscription ID for the maintainer's own smoke-test scan (NOT end-user scan credentials)"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_client_id" {
  description = "Azure service principal client ID for the maintainer's own smoke-test scan"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_tenant_id" {
  description = "Azure AD tenant ID for the maintainer's own smoke-test scan"
  type        = string
  sensitive   = true
  default     = null
}

variable "render_postgres_plan" {
  description = "Render Postgres plan tier. Confirm the real live tier against the Render dashboard before applying — this default is a guess based on docs/api-render-deploy.md, not a verified value"
  type        = string
  default     = "free"
}

variable "render_web_service_plan" {
  description = "Render web service plan tier. docs/api-render-deploy.md says \"Starter instance or higher\" — confirm the exact live tier against the dashboard before applying"
  type        = string
  default     = "starter"
}

variable "render_region" {
  description = "Render region for all managed services"
  type        = string
  default     = "oregon"
}
