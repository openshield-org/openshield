# OpenShield website

The project website, built with [Astro](https://astro.build) and deployed to GitHub
Pages. Every number on the site (rule count, domains, playbooks, contributors,
latest release, docs index) is extracted from the repository itself at build
time, so content stays correct without any manual editing.

## Local development

```bash
cd website
npm install
npm run dev        # http://localhost:4321/openshield/
```

Other scripts:

```bash
npm run build      # production build into dist/
npm run preview    # serve the production build locally
```

Requires Node 20+ (CI uses Node 22). The build reads `scanner/rules/`,
`playbooks/cli/`, `docs/`, `CHANGELOG.md` and the git history, so it must run
from a clone (not a tarball without history) for the contributor count.

## Publishing a blog post

Posts live in `src/content/blog/` as Markdown with frontmatter. Do not commit
to `dev` or `main` directly; both are protected.

Via the CMS (recommended):

1. Open `/admin/` on the deployed site and sign in with GitHub.
2. Create or edit a post under "Blog posts". Drafts are kept in the
   editorial workflow and are not published until merged.
3. Saving opens a pull request from `cms/<slug>` against `dev`, signed off
   for DCO. A maintainer reviews and merges it.
4. When the pull request merges into `dev`, GitHub Actions builds and
   deploys the site automatically (about 1-2 minutes). The site follows
   `dev`; `main` only receives release merges.

Local CMS development:

```bash
npm run dev                    # terminal 1
npx decap-server               # terminal 2 (local auth proxy on :8081)
```

Then open `http://localhost:4321/openshield/admin/` and click the login
button; it connects to the local proxy.

## Deployment pipeline

`.github/workflows/website.yml` runs on every pull request touching
`website/**` (build check) and deploys to GitHub Pages on pushes to `dev`.
There is no manual deploy step and no other environment to configure.

## One-time maintainer setup

1. In the repository settings, set Pages source to **GitHub Actions**.
2. Register a GitHub OAuth App for Decap CMS:
   - New OAuth App: https://github.com/settings/applications/new
   - Homepage URL: `https://openshield-org.github.io/openshield/admin/`
   - Authorization callback URL: `https://api.netlify.com/auth/done`
3. Put the Client ID into `public/admin/config.yml`, replacing the
   `REPLACE_WITH_GITHUB_OAUTH_APP_CLIENT_ID` placeholder. Commit that change
   through a pull request.

Decap uses `auth_type: pkce`, so no client secret or server-side token
exchange is needed.

## Content guidelines

- Plain, direct technical writing.
- No em dashes anywhere in site copy. Use commas, colons, or separate
  sentences instead.
- Frontmatter fields: `title`, `description`, `pubDate` (YYYY-MM-DD),
  optional `author`, `tags`, `draft`.

## Structure

```
website/
  astro.config.mjs        # site URL, base path, sitemap + RSS integrations
  src/content.config.ts   # blog collection schema
  src/content/blog/       # posts (managed by Decap CMS)
  src/layouts/Base.astro  # shared head, nav, footer
  src/components/         # one file per section of the landing page
  src/lib/repoData.ts     # build-time extraction of rules, docs, contributors
  src/lib/orbScene.ts     # hero visualization (three.js)
  src/pages/              # routes: /, /rules/, /docs/, /blog/, rss.xml, 404
  public/admin/           # Decap CMS (config + editor shell)
```
