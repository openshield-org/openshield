#!/usr/bin/env python3
"""
Generate a long-lived demo JWT for the OpenShield frontend.

The token is signed with the same JWT_SECRET used by the Render backend.
Set the result as VITE_JWT_TOKEN in the Vercel environment to allow the
frontend to authenticate against all /api/* endpoints.

Usage:
    JWT_SECRET=<your-production-secret> python scripts/generate_demo_jwt.py

The token has no expiry so it works without rotation. Treat it like a
password — set it only in the Vercel dashboard, never commit it to the repo.
"""

import os
import sys

try:
    import jwt
except ImportError:
    sys.exit("PyJWT is required: pip install pyjwt")

secret = os.environ.get("JWT_SECRET")
if not secret:
    sys.exit(
        "Error: JWT_SECRET environment variable is not set.\n"
        "Usage: JWT_SECRET=<your-production-secret> python scripts/generate_demo_jwt.py"
    )

token = jwt.encode(
    {"sub": "openshield-demo", "role": "viewer"},
    secret,
    algorithm="HS256",
)

print("\nGenerated demo JWT (set this as VITE_JWT_TOKEN on Vercel):\n")
print(token)
print(
    "\nNEVER commit this token or the JWT_SECRET to the repository.\n"
    "Set it only in the Vercel dashboard → Settings → Environment Variables.\n"
)
