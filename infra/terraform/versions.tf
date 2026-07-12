terraform {
  required_version = ">= 1.6"

  cloud {
    organization = "REPLACE_WITH_TFC_ORG"
    workspaces {
      name = "openshield"
    }
  }

  required_providers {
    render = {
      source  = "render-oss/render"
      version = "~> 1.8"
    }
    vercel = {
      source  = "vercel/vercel"
      version = ">= 4.8"
    }
  }
}

provider "render" {
  api_key  = var.render_api_key
  owner_id = var.render_owner_id
}

provider "vercel" {
  api_token = var.vercel_api_token
  team      = var.vercel_team
}
