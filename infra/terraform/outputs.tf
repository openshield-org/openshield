output "api_service_url" {
  description = "Live URL of the Render web service"
  value       = render_web_service.api.url
}

output "api_service_id" {
  description = "Render service ID, useful for the deploy-hook API (see #157)"
  value       = render_web_service.api.id
}

output "postgres_id" {
  description = "Render Postgres instance ID"
  value       = render_postgres.db.id
}

output "dashboard_project_id" {
  description = "Vercel project ID for the dashboard"
  value       = vercel_project.dashboard.id
}

output "website_project_id" {
  description = "Vercel project ID for the website"
  value       = vercel_project.website.id
}
