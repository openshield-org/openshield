---
title: "Under the Hood: Engineering a Dynamic Rule Orchestration Engine"
description: "A technical deep-dive into how OpenShield uses Python dynamic imports and SDK abstraction to scale security coverage."
pubDate: 2026-05-28
author: "OpenShield Engineering"
tags: ["engineering"]
draft: false
---

When we designed the OpenShield scanner, we knew that hardcoding security rules into the core engine was a recipe for technical debt. We needed a system where a security researcher could drop a new `.py` file into a folder and have it immediately active.

## The AzureClient Abstraction

Rules shouldn't deal with the complexities of Azure's many SDKs. We built the `AzureClient` wrapper in `scanner/azure_client.py` to provide typed accessors and unified auth.
