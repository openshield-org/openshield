# OpenShield Website

A data-driven static site for the OpenShield project. No build step required. Pure HTML, Tailwind CSS (CDN), and vanilla JavaScript.

## Live Site

`https://openshield-website.vercel.app`

---

## Deployment on Vercel

1. Vercel dashboard -> Add New Project -> Import the OpenShield repo
2. Set **Root Directory** to `website/`
3. Framework preset: **Other**
4. Build command: *(leave empty)*
5. Output directory: *(leave empty)*
6. Deploy

Vercel picks up `vercel.json` automatically. Every push to `main` triggers a redeploy.

---

## Adding Content

All content lives in `website/content.js`. Edit it directly on a branch and open a PR to `dev`. The built-in editor at the Blog Editor section can build and format the entry for you, but it no longer publishes for you directly — it does not ask for or use a GitHub token. Use "Export Entry" to get the formatted snippet, paste it into the right array in `website/content.js`, and open the PR yourself (see #297 — a page that can request a `repo`-scoped credential in the browser is a real risk on its own).

### Blog post

```javascript
{
    id: "unique-slug",
    title: "Post Title",
    date: "June 3, 2025",
    excerpt: "One or two sentences shown on the blog listing.",
    author: "Your Name or Team Name",
    image: "assets/blog/your-image.jpg",  // optional — commit the file to website/assets/blog/
    video: "https://www.youtube.com/embed/VIDEO_ID",  // optional — YouTube or Vimeo embed URL
    content: `
        <p class="mb-6">First paragraph.</p>
        <h3 class="text-2xl font-bold mb-4 text-slate-900 dark:text-white">A Subheading</h3>
        <p class="mb-6">More content. Markdown is also supported here via marked.js.</p>
    `
}
```

**Images in blog posts:**
- Cover image: commit to `website/assets/blog/` and set `image: "assets/blog/filename.jpg"`
- Inline images: use standard Markdown `![alt](assets/blog/filename.jpg)` inside the `content` field
- The editor no longer uploads images for you — commit the file to `website/assets/blog/` yourself as part of your PR.

**Video embeds:**
- Paste a YouTube watch URL (`https://www.youtube.com/watch?v=...`) or Vimeo URL (`https://vimeo.com/...`) into the `video` field
- The site converts it to an embed URL automatically
- Video is rendered above the post content, below the cover image
- Direct video file uploads are not supported — use YouTube or Vimeo as the host

### Community event

```javascript
{
    title: "Community Meetup #1",
    date: "July 10, 2025",
    location: "Online",
    link: "https://link-to-registration.com",
    status: "Upcoming"
}
```

### Contributor

```javascript
{
    name: "Jane Doe",
    role: "Security Researcher",
    handle: "janedoe"   // GitHub username — avatar is fetched automatically
}
```

### Release

```javascript
{
    version: "v0.2.0",
    date: "July 2025",
    type: "minor",      // major | minor | patch
    title: "Short description of the release",
    notes: [
        "What was added or changed",
        "Another notable change"
    ],
    github: "https://github.com/openshield-org/openshield/releases/tag/v0.2.0"
}
```

---

## Updating the Rules Gallery

The rules gallery is driven by the `siteContent.rules` array in `content.js`. When a new scanner rule is added to `scanner/rules/`, regenerate the array by running this from the repo root:

```bash
python3 -c "
import importlib.util, json, os
rules = []
for f in sorted(os.listdir('scanner/rules')):
    if not f.startswith('az_') or not f.endswith('.py'): continue
    spec = importlib.util.spec_from_file_location('r', 'scanner/rules/' + f)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    rules.append({'id': m.RULE_ID, 'name': m.RULE_NAME, 'severity': m.SEVERITY,
                  'category': m.CATEGORY, 'description': m.DESCRIPTION, 'frameworks': m.FRAMEWORKS})
print(json.dumps(rules, indent=2))
"
```

Paste the output as the `rules` array in `content.js`.

---

## What the editor covers

| Section | Editor support |
|---|---|
| Blog posts | Yes — Blog Post type (image preview, video embed, Markdown content) |
| Events | Yes — Community Event type |
| Contributors | Yes — New Contributor type |
| Releases | Yes — Release type |
| Roadmap | Manual edit of `content.js` only |
| Rules gallery | Manual edit of `content.js` only (use the script above) |
| Documentation pages | Manual edit of `content.js` only |

---

## Local development

Open `website/index.html` directly in a browser. No server or build step required. All dependencies load from CDN.

For a local server (avoids some CSP restrictions):

```bash
cd website
python3 -m http.server 8080
# open http://localhost:8080
```

---

## Testing

`node test_toEmbedUrl.mjs` runs the fast, pure-function tests (no browser needed).

Rendering, navigation, the removed GitHub-token flow, an XSS regression corpus, and
accessibility (axe + keyboard) are covered by Playwright:

```bash
cd website
npm install
npx playwright install --with-deps chromium   # first run only
npm run test:e2e
```

The suite serves the site itself on `127.0.0.1:4173` (see `playwright.config.js`) —
no separate server needs to be running first.

---

Core philosophy: keep it technical, keep it open.
