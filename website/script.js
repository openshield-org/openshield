/**
 * OpenShield Website Engine
 * Handles navigation, theme toggling, and the reactive terminal.
 */

// ------------------------------------------------------------------ //
// 1. Security & Helpers                                               //
// ------------------------------------------------------------------ //

function escapeHTML(str) {
    if (!str) return '';
    const p = document.createElement('p');
    p.textContent = str;
    return p.innerHTML;
}

// Every dynamically-built HTML string - whether it's this file's own
// template markup or markdown rendered from a blog post / the live editor
// preview - goes through this before it ever reaches innerHTML. DOMPurify's
// default config strips <script>, inline event-handler attributes
// (onerror=, onclick=, ...), javascript: URLs, and unknown/dangerous tags.
// It never contains an inline handler afterward, so it does not depend on
// the page's CSP allowing 'unsafe-inline' scripts to be safe - it's safe
// because nothing executable survives sanitization.
const SANITIZE_CONFIG = {
    ADD_TAGS: ['iframe'],
    ADD_ATTR: ['allowfullscreen', 'frameborder', 'loading', 'target'],
};

function sanitizeHTML(html) {
    return DOMPurify.sanitize(html, SANITIZE_CONFIG);
}

function setSafeHTML(el, html) {
    if (!el) return;
    el.innerHTML = sanitizeHTML(html);
}

function dedent(str) {
    if (!str) return '';
    const lines = str.split('\n');
    const first = lines.find(l => l.trim() !== '');
    if (!first) return str.trim();
    const baseIndent = first.match(/^\s*/)[0];

    let inPre = false;
    return lines.map(l => {
        let line = l.startsWith(baseIndent) ? l.substring(baseIndent.length) : l;

        // If we are not in a pre block, trim the line to move tags to column 0 for marked.js
        if (!inPre) {
            const trimmed = line.trim();
            if (trimmed.includes('<pre')) inPre = true;
            // Handle single-line pre blocks
            if (trimmed.includes('</pre')) inPre = false;
            return trimmed;
        } else {
            // Inside a pre block, preserve all whitespace
            if (line.includes('</pre')) inPre = false;
            return line;
        }
    }).join('\n').trim();
}

// Renders markdown to sanitized HTML, ready to assign to innerHTML directly.
// Centralised here so every markdown-derived surface (blog posts, docs
// pages, the live editor preview) sanitizes identically - there is exactly
// one path from untrusted markdown text to the DOM.
function renderMarkdown(raw) {
    const html = marked.parse(dedent(raw || ''));
    const clean = sanitizeHTML(html);
    const temp = document.createElement('div');
    temp.innerHTML = clean;
    temp.querySelectorAll('pre').forEach(pre => pre.classList.add('not-prose'));
    return temp.innerHTML;
}

// ------------------------------------------------------------------ //
// 2. Theme Management                                                  //
// ------------------------------------------------------------------ //

function initTheme() {
    const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');
    const themeToggleBtn = document.getElementById('theme-toggle');

    if (document.documentElement.classList.contains('dark')) {
        themeToggleLightIcon?.classList.remove('hidden');
        themeToggleDarkIcon?.classList.add('hidden');
    } else {
        themeToggleDarkIcon?.classList.remove('hidden');
        themeToggleLightIcon?.classList.add('hidden');
    }

    themeToggleBtn?.addEventListener('click', function() {
        themeToggleDarkIcon?.classList.toggle('hidden');
        themeToggleLightIcon?.classList.toggle('hidden');

        if (document.documentElement.classList.contains('dark')) {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('color-theme', 'light');
        } else {
            document.documentElement.classList.add('dark');
            localStorage.setItem('color-theme', 'dark');
        }
    });
}

// ------------------------------------------------------------------ //
// 3. Reactive Terminal Engine                                           //
// ------------------------------------------------------------------ //

async function typeWriter(text, element, speed = 40) {
    if (!element) return;
    for (let i = 0; i < text.length; i++) {
        element.textContent += text.charAt(i);
        await new Promise(resolve => setTimeout(resolve, speed));
    }
}

async function runTerminalSession() {
    const container = document.getElementById('terminal-content');
    if (!container) return;

    const sessions = siteContent.terminal;
    let currentSession = 0;

    while (true) {
        container.textContent = '';
        const session = sessions[currentSession];

        // Built with real DOM APIs, not an HTML string, so the
        // .command-text span genuinely exists for typeWriter() to type into
        // - no innerHTML/sanitizer round-trip needed for two static nodes.
        const cmdRow = document.createElement('div');
        cmdRow.className = 'flex items-start';
        const prompt = document.createElement('span');
        prompt.className = 'text-brand-500 mr-3 shrink-0';
        prompt.textContent = '❯';
        const cmdTextSpan = document.createElement('span');
        cmdTextSpan.className = 'command-text';
        cmdRow.append(prompt, cmdTextSpan);
        container.appendChild(cmdRow);

        await typeWriter(session.command, cmdTextSpan);
        await new Promise(resolve => setTimeout(resolve, 800));

        for (const line of session.output) {
            const outputRow = document.createElement('div');
            outputRow.className = 'text-slate-400 mt-1 pl-6 text-[12px] opacity-0 transition-opacity duration-300';
            outputRow.textContent = line;
            container.appendChild(outputRow);
            setTimeout(() => outputRow.classList.remove('opacity-0'), 50);
            await new Promise(resolve => setTimeout(resolve, 150));
        }

        await new Promise(resolve => setTimeout(resolve, 5000));
        currentSession = (currentSession + 1) % sessions.length;
    }
}

// ------------------------------------------------------------------ //
// 4. Routing & Navigation                                               //
// ------------------------------------------------------------------ //

function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
        setTimeout(() => { if(!section.classList.contains('active')) section.style.display = 'none'; }, 300);
    });

    const activeSection = document.getElementById(sectionId);
    if (activeSection) {
        activeSection.style.display = 'block';
        requestAnimationFrame(() => {
            activeSection.classList.add('active');
        });
    }

    if (sectionId === 'docs' && !window.location.hash.includes('/')) {
        showDocPage(siteContent.docs[0].id);
    }

    window.history.pushState(null, null, `#${sectionId}`);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showBlogPost(postId) {
    const post = siteContent.blog.find(p => p.id === postId);
    if (!post) return;

    const postContent = document.getElementById('post-content');
    if (postContent) {
        const imageHtml = post.image
            ? `<img src="${escapeHTML(post.image)}" class="w-full h-80 object-cover rounded-[2.5rem] mb-12 border border-slate-200 dark:border-white/10 shadow-2xl">`
            : '';
        const videoHtml = post.video
            ? `<div class="relative w-full aspect-video rounded-[2.5rem] overflow-hidden border border-slate-200 dark:border-white/10 shadow-2xl mb-12"><iframe src="${escapeHTML(post.video)}" class="absolute inset-0 w-full h-full" frameborder="0" allowfullscreen loading="lazy"></iframe></div>`
            : '';

        setSafeHTML(postContent, `
            ${imageHtml}
            ${videoHtml}
            <header class="mb-12 border-b border-slate-100 dark:border-white/5 pb-12">
                <div class="flex items-center text-brand-500 dark:text-brand-400 text-xs font-bold mb-6 tracking-[0.2em] uppercase">
                    <span>Technical Deep Dive</span>
                    <span class="mx-3 text-slate-300 dark:text-slate-700">|</span>
                    <time>${escapeHTML(post.date)}</time>
                </div>
                <h1 class="text-4xl md:text-6xl font-extrabold text-slate-900 dark:text-white tracking-tight leading-tight mb-8">${escapeHTML(post.title)}</h1>
                <p class="text-slate-500 text-sm">By ${escapeHTML(post.author)}</p>
            </header>
            <div class="prose prose-slate dark:prose-invert prose-lg max-none">
                ${renderMarkdown(post.content)}
            </div>
        `);
        showSection('post-detail');
        window.history.pushState(null, null, `#blog/${postId}`);
        if (window.lucide) lucide.createIcons();
    }
}

function handleRouting() {
    const hash = window.location.hash.replace('#', '');
    if (!hash || hash === 'home') {
        showSection('home');
    } else if (hash.startsWith('blog/')) {
        const postId = hash.split('/')[1];
        showBlogPost(postId);
    } else if (hash.startsWith('docs/')) {
        const docId = hash.split('/')[1];
        showSection('docs');
        showDocPage(docId);
    } else if (['rules', 'docs', 'blog', 'events', 'roadmap', 'releases', 'faq', 'community', 'blog-editor'].includes(hash)) {
        showSection(hash);
    } else {
        showSection('home');
    }
}

function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    menu?.classList.toggle('hidden');
}

// ------------------------------------------------------------------ //
// 5. Blog Editor                                                       //
// ------------------------------------------------------------------ //
//
// This editor no longer talks to the GitHub API from the browser (issue
// #297): a public page that asks any visitor for a classic, repo-scoped
// personal access token is a serious risk the moment anything on that page
// can be made to run attacker script - which is exactly the class of bug
// this same fix closes elsewhere on the page. "Export Entry" formats the
// entry the same way the old client-side flow did and hands it to the
// contributor to paste into website/content.js themselves, opening a PR the
// normal way. A properly scoped server-side publishing integration is
// explicitly out of scope here - see the issue for why.

function initEditor() {
    const form = document.getElementById('editor-form');
    if (!form) return;

    const fields = ['edit-title', 'edit-date', 'edit-author', 'edit-content', 'edit-excerpt', 'edit-location', 'edit-link', 'edit-status', 'edit-handle', 'edit-role', 'edit-video'];
    fields.forEach(id => {
        document.getElementById(id)?.addEventListener('input', updatePreview);
    });

    document.getElementById('edit-image-input')?.addEventListener('change', handleImageSelect);
    initImageDropZone();

    document.getElementById('export-entry-btn')?.addEventListener('click', exportEntry);
    document.getElementById('copy-entry-btn')?.addEventListener('click', copyExportedEntry);
}

let selectedImageFile = null;

const EMBED_ALLOWED_HOSTS = new Set(['www.youtube.com', 'youtube.com', 'player.vimeo.com']);

function toEmbedUrl(raw) {
    if (!raw) return '';
    const yt = raw.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    if (yt) return `https://www.youtube.com/embed/${yt[1]}`;
    const vi = raw.match(/vimeo\.com\/(\d+)/);
    if (vi) return `https://player.vimeo.com/video/${vi[1]}`;

    // Already-an-embed-URL fallback: verify the actual origin instead of a
    // substring check, which a crafted string (e.g. containing
    // "youtube.com/embed" anywhere but hosted elsewhere) can bypass and
    // break out of the iframe's src="..." attribute when interpolated.
    try {
        const parsed = new URL(raw);
        if (parsed.protocol === 'https:' && EMBED_ALLOWED_HOSTS.has(parsed.hostname)) {
            // Return the canonicalised href, not the raw input: a valid host
            // still lets an attribute-injection payload (e.g. a literal
            // double-quote) through on an allowed origin. parsed.href
            // percent-encodes quotes/spaces/brackets so the value is safe to
            // interpolate into the iframe src="..." attribute.
            return parsed.href;
        }
    } catch {
        // Not a valid absolute URL — fall through to reject below.
    }
    return '';
}

function processImageFile(file) {
    if (!file) return;
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
        alert('Only PNG, JPG, and WEBP images are supported.');
        return;
    }
    selectedImageFile = file;
    const reader = new FileReader();
    reader.onload = (e) => {
        const previewContainer = document.getElementById('image-preview-container');
        const previewImg = document.getElementById('image-preview-img');
        previewImg.src = e.target.result;
        previewContainer.classList.remove('hidden');
        updatePreview();
    };
    reader.readAsDataURL(file);
}

function handleImageSelect(event) {
    processImageFile(event.target.files[0]);
}

function initImageDropZone() {
    const zone = document.getElementById('image-drop-zone');
    if (!zone) return;
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('border-brand-500', 'bg-brand-500/5');
    });
    zone.addEventListener('dragleave', () => {
        zone.classList.remove('border-brand-500', 'bg-brand-500/5');
    });
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('border-brand-500', 'bg-brand-500/5');
        const file = e.dataTransfer?.files?.[0];
        if (file) processImageFile(file);
    });
}

function removeSelectedImage() {
    selectedImageFile = null;
    document.getElementById('edit-image-input').value = '';
    document.getElementById('image-preview-container').classList.add('hidden');
    updatePreview();
}

function toggleEditorFields() {
    const type = document.getElementById('edit-type').value;
    const isBlog        = type === 'blog';
    const isEvent       = type === 'event';
    const isContributor = type === 'contributor';
    const isRelease     = type === 'release';

    document.getElementById('field-id').classList.toggle('hidden', !isBlog);
    document.getElementById('field-excerpt').classList.toggle('hidden', !isBlog);
    document.getElementById('field-author').classList.toggle('hidden', !isBlog);
    document.getElementById('field-image').classList.toggle('hidden', !isBlog);
    document.getElementById('field-video').classList.toggle('hidden', !isBlog);
    document.getElementById('field-content').classList.toggle('hidden', !isBlog);

    document.getElementById('field-location').classList.toggle('hidden', !isEvent);
    document.getElementById('field-link').classList.toggle('hidden', !isEvent);
    document.getElementById('field-status').classList.toggle('hidden', !isEvent);

    document.getElementById('field-handle').classList.toggle('hidden', !isContributor);
    document.getElementById('field-role').classList.toggle('hidden', !isContributor);

    document.getElementById('field-release-version').classList.toggle('hidden', !isRelease);
    document.getElementById('field-release-type').classList.toggle('hidden', !isRelease);
    document.getElementById('field-release-notes').classList.toggle('hidden', !isRelease);
    document.getElementById('field-release-github').classList.toggle('hidden', !isRelease);

    const labelMap = { blog: 'Title', event: 'Event Name', contributor: 'Full Name', release: 'Release Title' };
    const placeholderMap = { blog: 'The Future of Cloud Security', event: 'Community Meetup #X', contributor: 'Jane Doe', release: 'Live Data Wiring and New Endpoints' };
    document.getElementById('label-title').textContent = labelMap[type] || 'Title';
    document.getElementById('edit-title').placeholder = placeholderMap[type] || '';

    resetExportedEntry();
    updatePreview();
}

function wireAvatarFallback(img) {
    if (!img) return;
    img.addEventListener('error', function onError() {
        this.removeEventListener('error', onError);
        this.src = 'https://github.com/github.png';
    });
}

function updatePreview() {
    const type = document.getElementById('edit-type').value;
    const title = document.getElementById('edit-title').value || (type === 'blog' ? 'Post Title' : 'Event Name');
    const date = document.getElementById('edit-date').value || 'Date';

    const preview = document.getElementById('editor-preview');
    if (!preview) return;

    if (type === 'blog') {
        const author = document.getElementById('edit-author').value || 'Author';
        const content = document.getElementById('edit-content').value || '_Content will appear here..._';
        const imageSrc = document.getElementById('image-preview-img').src;
        const imageHtml = !document.getElementById('image-preview-container').classList.contains('hidden')
            ? `<img src="${escapeHTML(imageSrc)}" class="w-full h-64 object-cover rounded-3xl mb-8 border border-slate-200 dark:border-white/10 shadow-lg">`
            : '';
        const videoRaw = document.getElementById('edit-video')?.value || '';
        const embedUrl = toEmbedUrl(videoRaw);
        const videoHtml = embedUrl
            ? `<div class="relative w-full aspect-video rounded-2xl overflow-hidden border border-slate-200 dark:border-white/10 shadow-lg mb-8"><iframe src="${escapeHTML(embedUrl)}" class="absolute inset-0 w-full h-full" frameborder="0" allowfullscreen loading="lazy"></iframe></div>`
            : '';

        setSafeHTML(preview, `
            ${imageHtml}
            <header class="mb-8 border-b border-slate-100 dark:border-white/5 pb-8">
                <div class="flex items-center text-brand-500 text-xs font-bold mb-4 uppercase tracking-widest">
                    <span>Blog Preview</span>
                    <span class="mx-2">|</span>
                    <span>${escapeHTML(date)}</span>
                </div>
                <h1 class="text-3xl font-extrabold text-slate-900 dark:text-white mb-4">${escapeHTML(title)}</h1>
                <p class="text-slate-500 text-sm">By ${escapeHTML(author)}</p>
            </header>
            ${videoHtml}
            <div class="prose prose-slate dark:prose-invert">
                ${renderMarkdown(content)}
            </div>
        `);
    } else if (type === 'event') {
        const location = document.getElementById('edit-location').value || 'Location';
        const status = document.getElementById('edit-status').value || 'Upcoming';
        setSafeHTML(preview, `
            <div class="flex flex-col items-center justify-center text-center py-20">
                <div class="inline-flex items-center px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-[10px] font-bold uppercase tracking-widest mb-6">
                    Event Preview
                </div>
                <h1 class="text-4xl font-extrabold text-slate-900 dark:text-white mb-4">${escapeHTML(title)}</h1>
                <p class="text-xl text-slate-500 mb-8">${escapeHTML(date)} • ${escapeHTML(location)}</p>
                <div class="px-6 py-2 rounded-xl bg-slate-900 dark:bg-white text-white dark:text-slate-900 font-bold text-sm">
                    ${escapeHTML(status)}
                </div>
            </div>
        `);
    } else if (type === 'contributor') {
        const handle = document.getElementById('edit-handle').value || 'username';
        const role = document.getElementById('edit-role').value || 'Contributor';
        setSafeHTML(preview, `
            <div class="flex flex-col items-center justify-center text-center py-20">
                <div class="inline-flex items-center px-3 py-1 rounded-full bg-slate-500/10 border border-slate-500/20 text-slate-500 text-[10px] font-bold uppercase tracking-widest mb-8">
                    Contributor Preview
                </div>
                <div class="relative mb-6">
                    <img id="contributor-preview-avatar" src="${escapeHTML(`https://github.com/${handle}.png`)}" alt="${escapeHTML(handle)}" class="w-24 h-24 rounded-full border-4 border-slate-200 dark:border-white/10 shadow-xl">
                    <div class="absolute -bottom-2 -right-2 w-8 h-8 bg-slate-900 rounded-full flex items-center justify-center border-2 border-white dark:border-dark-950">
                        <i class="fab fa-github text-white text-xs"></i>
                    </div>
                </div>
                <h1 class="text-3xl font-extrabold text-slate-900 dark:text-white mb-2">${escapeHTML(title)}</h1>
                <p class="text-slate-500 font-medium mb-1">${escapeHTML(role)}</p>
                <p class="text-brand-500 text-sm font-mono">@${escapeHTML(handle)}</p>
            </div>
        `);
        // The onerror avatar fallback used to be an inline attribute in the
        // template string itself; DOMPurify strips inline event-handler
        // attributes from sanitized output by design (that's what closes the
        // XSS this whole fix is about), so it's wired up here instead, the
        // same way every other dynamic click/error handler on this page now is.
        wireAvatarFallback(document.getElementById('contributor-preview-avatar'));
    } else if (type === 'release') {
        const version = document.getElementById('edit-release-version').value || 'vX.Y.Z';
        const releaseType = document.getElementById('edit-release-type').value || 'minor';
        const notes = (document.getElementById('edit-release-notes').value || '').split('\n').filter(l => l.trim());
        setSafeHTML(preview, `
            <div class="py-8">
                <div class="flex items-center gap-4 mb-4">
                    <span class="font-mono text-2xl font-extrabold text-slate-900 dark:text-white">${escapeHTML(version)}</span>
                    <span class="px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded-full">Latest</span>
                    <span class="px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest bg-blue-500/10 text-blue-500 border border-blue-500/20 rounded-full">${escapeHTML(releaseType)}</span>
                </div>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white mb-4">${escapeHTML(title)}</h3>
                <ul class="space-y-2">
                    ${notes.map(n => `
                        <li class="flex items-start gap-3 text-sm text-slate-600 dark:text-slate-400">
                            <span class="text-emerald-500 mt-0.5">+</span>
                            <span>${escapeHTML(n)}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `);
    }

    resetExportedEntry();
}

function buildEntry() {
    const type = document.getElementById('edit-type').value;

    if (type === 'blog') {
        const videoRaw = document.getElementById('edit-video')?.value || '';
        const entry = {
            id: document.getElementById('edit-id').value,
            title: document.getElementById('edit-title').value,
            date: document.getElementById('edit-date').value,
            excerpt: document.getElementById('edit-excerpt').value,
            author: document.getElementById('edit-author').value,
            // Images are no longer uploaded from the browser (that required
            // the token this fix removes). Left blank; exportEntry()'s note
            // tells the contributor to add the file under
            // website/assets/blog/ and fill this in as part of their PR.
            image: '',
            video: toEmbedUrl(videoRaw) || undefined,
            content: document.getElementById('edit-content').value
        };
        if (!entry.id || !entry.title || !entry.content) {
            return { error: 'ID, Title, and Content are required for blog posts.' };
        }
        return { type, entry, arrayKey: 'blog' };
    } else if (type === 'event') {
        const entry = {
            title: document.getElementById('edit-title').value,
            date: document.getElementById('edit-date').value,
            location: document.getElementById('edit-location').value,
            link: document.getElementById('edit-link').value,
            status: document.getElementById('edit-status').value
        };
        if (!entry.title || !entry.date) {
            return { error: 'Title and Date are required for events.' };
        }
        return { type, entry, arrayKey: 'events' };
    } else if (type === 'contributor') {
        const entry = {
            name: document.getElementById('edit-title').value,
            role: document.getElementById('edit-role').value,
            handle: document.getElementById('edit-handle').value
        };
        if (!entry.name || !entry.handle) {
            return { error: 'Name and GitHub Handle are required for contributors.' };
        }
        return { type, entry, arrayKey: 'contributors' };
    } else if (type === 'release') {
        const notesRaw = document.getElementById('edit-release-notes').value || '';
        const entry = {
            version: document.getElementById('edit-release-version').value,
            date: document.getElementById('edit-date').value,
            type: document.getElementById('edit-release-type').value,
            title: document.getElementById('edit-title').value,
            notes: notesRaw.split('\n').map(l => l.trim()).filter(l => l.length > 0),
            github: document.getElementById('edit-release-github').value
        };
        if (!entry.version || !entry.title || entry.notes.length === 0) {
            return { error: 'Version, Title, and at least one release note are required.' };
        }
        return { type, entry, arrayKey: 'releases' };
    }
    return { error: 'Unknown entry type.' };
}

function resetExportedEntry() {
    const output = document.getElementById('export-entry-output');
    const copyBtn = document.getElementById('copy-entry-btn');
    const note = document.getElementById('export-entry-note');
    output?.classList.add('hidden');
    copyBtn?.classList.add('hidden');
    if (output) output.value = '';
    if (note) note.textContent = '';
}

function exportEntry() {
    const result = buildEntry();
    const note = document.getElementById('export-entry-note');
    const output = document.getElementById('export-entry-output');
    const copyBtn = document.getElementById('copy-entry-btn');
    if (!output || !note || !copyBtn) return;

    if (result.error) {
        output.classList.add('hidden');
        copyBtn.classList.add('hidden');
        note.textContent = result.error;
        return;
    }

    const snippet = `${JSON.stringify(result.entry, null, 4)},`;
    output.value = snippet;
    output.classList.remove('hidden');
    copyBtn.classList.remove('hidden');

    const imageNote = (result.type === 'blog' && selectedImageFile)
        ? ' Your selected image is not uploaded automatically — add it under website/assets/blog/ in your PR and set the "image" field above to its path.'
        : '';
    note.textContent = `Paste this into the "${result.arrayKey}" array in website/content.js, then open a pull request.${imageNote}`;
}

async function copyExportedEntry() {
    const output = document.getElementById('export-entry-output');
    const note = document.getElementById('export-entry-note');
    if (!output || !output.value) return;
    try {
        await navigator.clipboard.writeText(output.value);
        if (note) {
            const original = note.textContent;
            note.textContent = 'Copied to clipboard.';
            setTimeout(() => { note.textContent = original; }, 2000);
        }
    } catch {
        output.select();
    }
}

// ------------------------------------------------------------------ //
// 6. Content Rendering                                                 //
// ------------------------------------------------------------------ //

function renderEcosystem() {
    const container = document.getElementById('ecosystem-container');
    if (!container) return;

    setSafeHTML(container, siteContent.ecosystem.map((item, idx) => {
        const isLarge = idx === 0 || idx === 3;
        const colSpan = isLarge ? 'md:col-span-8' : 'md:col-span-4';

        const iconHtml = item.icon === 'shield'
            ? `<i class="fas fa-shield-halved fa-fw text-2xl"></i>`
            : `<i data-lucide="${escapeHTML(item.icon)}" class="w-7 h-7"></i>`;

        return `
            <div class="${colSpan} bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 p-10 rounded-[2.5rem] backdrop-blur-sm group hover:bg-slate-50 dark:hover:bg-white/[0.07] transition-all shadow-sm">
                <div class="w-14 h-14 bg-${item.color}-500/10 text-${item.color}-500 dark:text-${item.color}-400 rounded-2xl flex items-center justify-center mb-8 border border-${item.color}-500/20">
                    ${iconHtml}
                </div>
                <h3 class="text-2xl font-bold text-slate-900 dark:text-white mb-4">${escapeHTML(item.title)}</h3>
                <p class="text-slate-600 dark:text-slate-400 leading-relaxed">${escapeHTML(item.description)}</p>
            </div>
        `;
    }).join(''));

    if (window.lucide) lucide.createIcons();
}

function renderRules() {
    const container = document.getElementById('rules-container');
    if (!container) return;

    const searchTerm = (document.getElementById('rule-search')?.value || '').toLowerCase();
    const filterFw = document.getElementById('rule-filter')?.value || 'all';

    const filteredRules = siteContent.rules.filter(rule => {
        const matchesSearch = rule.id.toLowerCase().includes(searchTerm) ||
                              rule.name.toLowerCase().includes(searchTerm) ||
                              rule.category.toLowerCase().includes(searchTerm) ||
                              rule.description.toLowerCase().includes(searchTerm);

        const matchesFw = filterFw === 'all' || rule.frameworks[filterFw] !== undefined;

        return matchesSearch && matchesFw;
    });

    if (filteredRules.length === 0) {
        setSafeHTML(container, `
            <div class="col-span-full text-center py-12 bg-slate-50 dark:bg-white/5 border border-dashed border-slate-300 dark:border-white/10 rounded-3xl">
                <p class="text-slate-500">No rules match your search criteria.</p>
            </div>
        `);
        return;
    }

    setSafeHTML(container, filteredRules.map(rule => `
        <div class="bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 p-8 rounded-3xl hover:border-brand-500/50 transition-all group shadow-sm flex flex-col h-full">
            <div class="flex justify-between items-start mb-6">
                <span class="text-[10px] font-bold tracking-widest text-slate-400 uppercase">${escapeHTML(rule.id)}</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-${rule.severity === 'HIGH' ? 'red' : rule.severity === 'MEDIUM' ? 'amber' : 'blue'}-500/10 text-${rule.severity === 'HIGH' ? 'red' : rule.severity === 'MEDIUM' ? 'amber' : 'blue'}-500 border border-${rule.severity === 'HIGH' ? 'red' : rule.severity === 'MEDIUM' ? 'amber' : 'blue'}-500/20">${escapeHTML(rule.severity)}</span>
            </div>
            <h3 class="text-xl font-bold text-slate-900 dark:text-white mb-3 group-hover:text-brand-500 transition-colors">${escapeHTML(rule.name)}</h3>
            <p class="text-slate-600 dark:text-slate-400 text-sm mb-6 line-clamp-3 flex-grow">${escapeHTML(rule.description)}</p>
            <div class="flex flex-wrap gap-2 mt-auto">
                ${Object.entries(rule.frameworks).map(([f, v]) => `
                    <span class="px-2 py-1 rounded-md bg-slate-100 dark:bg-white/5 text-[10px] font-mono text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-white/10">
                        ${escapeHTML(f)}: ${escapeHTML(String(v))}
                    </span>
                `).join('')}
            </div>
        </div>
    `).join(''));

    if (window.lucide) lucide.createIcons();
}

function renderDocsSidebar() {
    const nav = document.getElementById('docs-nav');
    if (!nav) return;

    setSafeHTML(nav, siteContent.docs.map(doc => `
        <button data-doc-id="${escapeHTML(doc.id)}" id="nav-${escapeHTML(doc.id)}" class="doc-nav-btn block w-full text-left px-5 py-3 text-sm font-semibold text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-white/5 rounded-2xl transition-all flex items-center group">
            <span class="w-1.5 h-1.5 rounded-full bg-transparent group-hover:bg-brand-500 mr-3 transition-colors"></span>
            ${escapeHTML(doc.title)}
        </button>
    `).join(''));

    nav.querySelectorAll('[data-doc-id]').forEach(btn => {
        btn.addEventListener('click', () => showDocPage(btn.dataset.docId));
    });
}

function showDocPage(docId) {
    const doc = siteContent.docs.find(d => d.id === docId);
    if (!doc) return;

    const container = document.getElementById('docs-content-container');
    if (container) {
        setSafeHTML(container, `
            ${renderMarkdown(doc.content)}
            <div class="mt-16 pt-8 border-t border-slate-200 dark:border-white/10 flex flex-col sm:flex-row justify-between items-center gap-6 not-prose">
                <div>
                    <p class="text-sm font-bold text-slate-900 dark:text-white mb-1">Help us improve these docs</p>
                    <p class="text-xs text-slate-500">Notice an issue or want to add a section? This page is community-maintained.</p>
                </div>
                <a href="https://github.com/openshield-org/openshield/edit/dev/website/content.js" target="_blank" rel="noopener" class="flex items-center px-5 py-2.5 bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 rounded-xl text-sm font-bold text-slate-900 dark:text-white hover:bg-slate-100 dark:hover:bg-white/10 hover:border-brand-500/50 transition-all group shadow-sm no-underline">
                    <i data-lucide="edit-3" class="w-4 h-4 mr-2 text-brand-500 group-hover:scale-110 transition-transform"></i>
                    Edit this page on GitHub
                </a>
            </div>
        `);
        window.history.pushState(null, null, `#docs/${docId}`);

        // Update active state in sidebar
        document.querySelectorAll('.doc-nav-btn').forEach(btn => {
            btn.classList.remove('bg-brand-500/10', 'text-brand-600', 'dark:text-white', 'shadow-sm');
            btn.querySelector('span')?.classList.remove('bg-brand-500');
        });

        const activeBtn = document.getElementById(`nav-${docId}`);
        if (activeBtn) {
            activeBtn.classList.add('bg-brand-500/10', 'text-brand-600', 'dark:text-white', 'shadow-sm');
            activeBtn.querySelector('span')?.classList.add('bg-brand-500');
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
        if (window.lucide) lucide.createIcons();
    }
}

function renderBlog() {
    const container = document.getElementById('blog-container');
    if (!container) return;

    setSafeHTML(container, siteContent.blog.map(post => {
        const imageHtml = post.image
            ? `<img src="${escapeHTML(post.image)}" class="w-full h-48 object-cover rounded-2xl mb-6 border border-slate-200 dark:border-white/10 shadow-sm">`
            : '';
        return `
            <article data-post-id="${escapeHTML(post.id)}" class="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 p-8 rounded-3xl hover:border-brand-500/50 transition-all cursor-pointer group">
                ${imageHtml}
                <h3 class="text-2xl font-bold mb-4 text-slate-900 dark:text-white group-hover:text-brand-500 transition-colors">${escapeHTML(post.title)}</h3>
                <p class="text-slate-600 dark:text-slate-400 leading-relaxed mb-6 text-sm">${escapeHTML(post.excerpt)}</p>
                <button class="text-brand-600 font-bold text-xs uppercase tracking-widest flex items-center">
                    Read Full Deep Dive
                    <i data-lucide="arrow-right" class="w-4 h-4 ml-2 group-hover:translate-x-1 transition"></i>
                </button>
            </article>
        `;
    }).join(''));

    container.querySelectorAll('[data-post-id]').forEach(article => {
        article.addEventListener('click', () => showBlogPost(article.dataset.postId));
    });

    if (window.lucide) lucide.createIcons();
}

function renderEvents() {
    const container = document.getElementById('events-container');
    if (!container || !siteContent.events) return;

    if (siteContent.events.length === 0) {
        setSafeHTML(container, `
            <div class="text-center py-12 bg-slate-50 dark:bg-white/5 border border-dashed border-slate-300 dark:border-white/10 rounded-3xl">
                <p class="text-slate-500">No upcoming events. Stay tuned!</p>
            </div>
        `);
        return;
    }

    setSafeHTML(container, siteContent.events.map(event => `
        <div class="flex flex-col md:flex-row justify-between items-center p-8 bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 rounded-3xl hover:border-brand-500/50 transition-all gap-6">
            <div>
                <h3 class="text-xl font-bold text-slate-900 dark:text-white mb-2">${escapeHTML(event.title)}</h3>
                <p class="text-slate-500 text-sm">${escapeHTML(event.date)} • ${escapeHTML(event.location)}</p>
            </div>
            <div class="flex items-center gap-4">
                <span class="px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-[10px] font-bold uppercase tracking-widest">
                    ${escapeHTML(event.status)}
                </span>
                <a href="${escapeHTML(event.link)}" target="_blank" rel="noopener" class="bg-slate-900 dark:bg-white text-white dark:text-slate-900 px-6 py-2 rounded-xl font-bold text-sm hover:scale-105 transition-all">
                    Register
                </a>
            </div>
        </div>
    `).join(''));
}

function renderRoadmap() {
    if (!siteContent.roadmap) return;
    const groups = { Shipped: [], Now: [], Next: [], Later: [] };

    siteContent.roadmap.forEach(item => {
        if (groups[item.status]) groups[item.status].push(item);
    });

    const statusConfig = {
        'Shipped': { color: 'slate', dot: 'bg-slate-400' },
        'Now':     { color: 'emerald', dot: 'bg-emerald-500' },
        'Next':    { color: 'purple', dot: 'bg-purple-500' },
        'Later':   { color: 'slate', dot: 'bg-slate-400' }
    };

    ['Shipped', 'Now', 'Next', 'Later'].forEach(status => {
        const container = document.getElementById(`roadmap-${status.toLowerCase()}`);
        if (!container) return;

        const config = statusConfig[status];

        setSafeHTML(container, groups[status].map(item => `
            <div class="p-4 bg-slate-50 dark:bg-white/[0.03] border border-slate-200 dark:border-white/5 rounded-2xl group transition-all hover:border-${config.color}-500/30">
                <div class="flex justify-between items-start mb-2">
                    <span class="text-[10px] font-bold tracking-widest text-slate-400 uppercase">${escapeHTML(item.category)}</span>
                    ${status === 'Shipped' ? '<span class="text-[8px] font-bold text-emerald-500 uppercase tracking-widest">Done</span>' : ''}
                </div>
                <h4 class="text-sm font-bold text-slate-900 dark:text-white group-hover:text-${config.color}-500 transition-colors leading-tight">${escapeHTML(item.title)}</h4>
            </div>
        `).join(''));
    });
}

function renderReleases() {
    const container = document.getElementById('releases-container');
    if (!container || !siteContent.releases) return;

    const typeColors = { major: 'blue', minor: 'emerald', patch: 'slate' };

    setSafeHTML(container, siteContent.releases.map((release, idx) => {
        const color = typeColors[release.type] || 'slate';
        const isLatest = idx === 0;
        return `
            <div class="bg-white dark:bg-white/[0.02] border ${isLatest ? 'border-emerald-500/30' : 'border-slate-200 dark:border-white/10'} rounded-[2.5rem] p-8 shadow-sm transition-all hover:shadow-md">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                    <div class="flex items-center gap-4">
                        <span class="font-mono text-2xl font-extrabold text-slate-900 dark:text-white">${escapeHTML(release.version)}</span>
                        ${isLatest ? '<span class="px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded-full">Latest</span>' : ''}
                        <span class="px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest bg-${color}-500/10 text-${color}-500 border border-${color}-500/20 rounded-full">${escapeHTML(release.type)}</span>
                    </div>
                    <div class="flex items-center gap-4">
                        <span class="text-sm text-slate-500">${escapeHTML(release.date)}</span>
                        <a href="${escapeHTML(release.github)}" target="_blank" rel="noopener" class="flex items-center gap-2 px-4 py-2 text-xs font-bold border border-slate-200 dark:border-white/10 rounded-xl hover:border-brand-500/50 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-all">
                            <i data-lucide="github" class="w-3.5 h-3.5"></i> View on GitHub
                        </a>
                    </div>
                </div>
                <h3 class="text-lg font-bold text-slate-900 dark:text-white mb-4">${escapeHTML(release.title)}</h3>
                <ul class="space-y-2">
                    ${release.notes.map(note => `
                        <li class="flex items-start gap-3 text-sm text-slate-600 dark:text-slate-400">
                            <i data-lucide="check" class="w-4 h-4 text-emerald-500 mt-0.5 shrink-0"></i>
                            <span>${escapeHTML(note)}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `;
    }).join(''));

    if (window.lucide) lucide.createIcons();
}

function renderFAQ() {
    const container = document.getElementById('faq-container');
    if (!container || !siteContent.faq) return;

    setSafeHTML(container, siteContent.faq.map((item, idx) => `
        <div class="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 rounded-2xl overflow-hidden transition-all">
            <button
                data-faq-idx="${idx}"
                class="w-full flex items-center justify-between px-8 py-6 text-left group"
            >
                <span class="text-base font-bold text-slate-900 dark:text-white group-hover:text-brand-500 transition-colors pr-8">${escapeHTML(item.question)}</span>
                <i data-lucide="chevron-down" id="faq-icon-${idx}" class="w-5 h-5 text-slate-400 shrink-0 transition-transform duration-200"></i>
            </button>
            <div id="faq-answer-${idx}" class="hidden px-8 pb-6">
                <p class="text-slate-600 dark:text-slate-400 leading-relaxed text-sm">${escapeHTML(item.answer)}</p>
            </div>
        </div>
    `).join(''));

    container.querySelectorAll('[data-faq-idx]').forEach(btn => {
        btn.addEventListener('click', () => toggleFAQ(Number(btn.dataset.faqIdx)));
    });

    if (window.lucide) lucide.createIcons();
}

function toggleFAQ(idx) {
    const answer = document.getElementById(`faq-answer-${idx}`);
    const icon   = document.getElementById(`faq-icon-${idx}`);
    if (!answer || !icon) return;
    const isOpen = !answer.classList.contains('hidden');
    answer.classList.toggle('hidden', isOpen);
    icon.style.transform = isOpen ? '' : 'rotate(180deg)';
}

function renderShowcase() {
    const container = document.getElementById('showcase-container');
    if (!container || !siteContent.showcase) return;

    setSafeHTML(container, siteContent.showcase.map(item => `
        <div class="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/10 p-8 rounded-3xl hover:border-brand-500/50 transition-all text-center">
            <div class="w-16 h-16 mx-auto bg-slate-50 dark:bg-white/5 text-slate-900 dark:text-white rounded-2xl flex items-center justify-center mb-6">
                <i data-lucide="${escapeHTML(item.icon)}" class="w-8 h-8"></i>
            </div>
            <h3 class="text-xl font-bold text-slate-900 dark:text-white mb-2">${escapeHTML(item.name)}</h3>
            <p class="text-slate-500 text-sm">${escapeHTML(item.description)}</p>
        </div>
    `).join(''));

    if (window.lucide) lucide.createIcons();
}

async function renderContributors() {
    const container = document.getElementById('contributors-container');
    if (!container || !siteContent.contributors) return;

    // Strictly show only the primary release team
    setSafeHTML(container, siteContent.contributors.map(c => `
        <a href="https://github.com/${escapeHTML(c.handle)}" target="_blank" rel="noopener" title="${escapeHTML(c.name)} (${escapeHTML(c.role)})" class="group relative">
            <img src="${escapeHTML(`https://github.com/${c.handle}.png`)}" alt="${escapeHTML(c.name)}" class="w-14 h-14 rounded-full border-2 border-slate-900 dark:border-white/10 transition-transform group-hover:scale-110 group-hover:border-slate-400 group-hover:z-10 relative">
            <div class="absolute -bottom-10 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-[10px] py-1 px-2 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-20">
                ${escapeHTML(c.name)}
            </div>
        </a>
    `).join(''));
}

// Initialization
window.addEventListener('load', () => {
    initTheme();
    handleRouting();
    renderEcosystem();
    renderRules();
    renderDocsSidebar();
    renderBlog();
    renderEvents();
    renderRoadmap();
    renderReleases();
    renderFAQ();
    renderShowcase();
    renderContributors();
    initEditor();
    runTerminalSession();
    if (window.lucide) lucide.createIcons();
});

// ------------------------------------------------------------------ //
// 8. Interactive Playground                                            //
// ------------------------------------------------------------------ //

function setButtonContent(btn, iconName, label, extraIconClass) {
    if (!btn) return;
    btn.textContent = '';
    if (iconName) {
        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', iconName);
        icon.className = `w-4 h-4 mr-2 ${extraIconClass || ''}`.trim();
        btn.appendChild(icon);
    }
    btn.appendChild(document.createTextNode(label));
}

async function runMockScan() {
    const btn = document.getElementById('btn-run-mock');
    const terminal = document.getElementById('mock-terminal-output');
    const feed = document.getElementById('pg-findings-feed');
    const scoreEl = document.getElementById('pg-score');
    const statusEl = document.getElementById('pg-status');
    const counters = {
        crit: document.getElementById('pg-count-crit'),
        warn: document.getElementById('pg-count-warn'),
        pass: document.getElementById('pg-count-pass')
    };

    if (!btn || !terminal || !feed) return;

    const env = document.getElementById('pg-env').value;
    const framework = document.getElementById('pg-framework').value;

    // Reset UI
    btn.disabled = true;
    setButtonContent(btn, 'loader', 'Running...', 'animate-spin');
    setSafeHTML(terminal, `<div class="text-brand-400 font-bold">$ openshield scan --env ${escapeHTML(env)} --pkg ${escapeHTML(framework)}</div>`);
    feed.textContent = '';
    scoreEl.textContent = '100';
    scoreEl.className = 'text-6xl font-black text-emerald-500 transition-colors duration-500';
    Object.values(counters).forEach(c => c.textContent = '0');
    statusEl.textContent = 'Status: Initializing...';
    statusEl.className = 'text-[10px] font-bold text-brand-500 uppercase tracking-tighter';

    if (window.lucide) lucide.createIcons();

    const events = [
        { type: 'log', val: '[INFO] Initializing OpenShield Core v0.1.0...', delay: 400 },
        { type: 'log', val: '[INFO] Loading security modules for ' + framework.toUpperCase() + '...', delay: 600 },
        { type: 'log', val: '[INFO] Authenticating with Azure Resource Manager...', delay: 800 },
        { type: 'status', val: 'Status: Discovery Phase', color: 'text-blue-500' },
        { type: 'log', val: '[INFO] Discovering resources in subscription \'mock-sub-123\'...', delay: 500 },
        { type: 'log', val: '[OK] Identified: 12 VMs, 8 Storage, 4 SQL Servers.', delay: 300 },
        { type: 'status', val: 'Status: Analysis Running', color: 'text-amber-500' },
        { type: 'finding', id: 'AZ-NET-001', name: 'Inbound SSH Open to Internet', sev: 'CRITICAL', desc: 'Port 22 is unrestricted on vm-prod-bastion.', scoreDrop: 15, delay: 1200 },
        { type: 'log', val: '[CRITICAL] AZ-NET-001 detected on resource: vm-prod-bastion', delay: 100 },
        { type: 'finding', id: 'AZ-STOR-001', name: 'Public Blob Access Enabled', sev: 'CRITICAL', desc: 'Anonymous read access is allowed on storage-assets-01.', scoreDrop: 12, delay: 1500 },
        { type: 'log', val: '[CRITICAL] AZ-STOR-001 detected on resource: storage-assets-01', delay: 100 },
        { type: 'finding', id: 'AZ-KV-004', name: 'Key Vault Soft Delete Disabled', sev: 'WARNING', desc: 'kv-prod-secrets has no deletion protection.', scoreDrop: 5, delay: 1000 },
        { type: 'log', val: '[WARN] AZ-KV-004 detected on resource: kv-prod-secrets', delay: 100 },
        { type: 'log', val: '[OK] AZ-DB-001: SQL Server Transparent Data Encryption is Enabled.', delay: 400, typeUpdate: 'pass' },
        { type: 'finding', id: 'AZ-DB-002', name: 'SQL Server Auditing Disabled', sev: 'WARNING', desc: 'Audit logs are not being captured for users-db.', scoreDrop: 8, delay: 1400 },
        { type: 'log', val: '[WARN] AZ-DB-002 detected on resource: users-db', delay: 100 },
        { type: 'log', val: '[INFO] Finalizing compliance report...', delay: 800 },
        { type: 'log', val: '\n--- SCAN COMPLETE ---', delay: 100 },
        { type: 'log', val: '[SUCCESS] 2 Critical, 2 Warning findings identified.', delay: 100 },
        { type: 'log', val: '[INFO] Report generated: openshield_report_v1.pdf', delay: 100 },
        { type: 'status', val: 'Status: Completed', color: 'text-emerald-500' }
    ];

    let currentScore = 100;
    let stats = { crit: 0, warn: 0, pass: 0 };

    for (const event of events) {
        if (event.delay) await new Promise(r => setTimeout(r, event.delay));

        if (event.type === 'log') {
            const div = document.createElement('div');
            div.className = event.val.includes('CRITICAL') ? 'text-red-400' : (event.val.includes('WARN') ? 'text-amber-400' : (event.val.includes('[OK]') ? 'text-emerald-400' : 'text-slate-400'));
            div.textContent = event.val;
            terminal.appendChild(div);
            terminal.scrollTop = terminal.scrollHeight;
            if (event.typeUpdate === 'pass') {
                stats.pass++;
                counters.pass.textContent = stats.pass;
            }
        }
        else if (event.type === 'status') {
            statusEl.textContent = event.val;
            statusEl.className = 'text-[10px] font-bold uppercase tracking-tighter ' + event.color;
        }
        else if (event.type === 'finding') {
            // Update Score
            const startScore = currentScore;
            currentScore -= event.scoreDrop;
            animateValue(scoreEl, startScore, currentScore, 500);

            // Color logic for score
            if (currentScore < 60) scoreEl.className = 'text-6xl font-black text-red-500 animate-score-pop';
            else if (currentScore < 85) scoreEl.className = 'text-6xl font-black text-amber-500 animate-score-pop';

            // Update Counters
            const key = event.sev === 'CRITICAL' ? 'crit' : 'warn';
            stats[key]++;
            counters[key].textContent = stats[key];

            // Add Card — event fields are all from the fixed, hardcoded
            // `events` array above (never from siteContent or user input),
            // but escapeHTML() is used anyway so this stays correct if that
            // ever changes.
            const card = document.createElement('div');
            card.className = 'bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/10 p-4 rounded-2xl animate-slide-in-right shadow-sm';
            const color = event.sev === 'CRITICAL' ? 'red' : 'amber';
            setSafeHTML(card, `
                <div class="flex justify-between items-start mb-2">
                    <span class="text-[8px] font-bold text-slate-400 uppercase tracking-widest">${escapeHTML(event.id)}</span>
                    <span class="px-1.5 py-0.5 rounded text-[7px] font-bold bg-${color}-500/10 text-${color}-500 border border-${color}-500/20">${escapeHTML(event.sev)}</span>
                </div>
                <h5 class="text-xs font-bold text-slate-900 dark:text-white mb-1">${escapeHTML(event.name)}</h5>
                <p class="text-[10px] text-slate-500 dark:text-slate-400 leading-tight">${escapeHTML(event.desc)}</p>
            `);
            feed.prepend(card);
        }
    }

    btn.disabled = false;
    setButtonContent(btn, 'rotate-cw', 'Re-run Scan');
    if (window.lucide) lucide.createIcons();
}

function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.textContent = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

window.addEventListener('popstate', handleRouting);
document.getElementById('mobile-menu-btn')?.addEventListener('click', toggleMobileMenu);

// ------------------------------------------------------------------ //
// Static navigation/control wiring                                     //
// ------------------------------------------------------------------ //
// This file's own static markup used inline onclick/onchange/oninput
// attributes for these controls until issue #297: CSP's script-src no
// longer permits 'unsafe-inline', so every one of them is wired here
// instead, off data-* attributes/ids present in the fixed HTML this file
// ships (never generated from remote/user data - see setSafeHTML()).

document.querySelectorAll('[data-nav-section]').forEach((el) => {
    el.addEventListener('click', () => {
        showSection(el.dataset.navSection);
        if ('closeMobileMenu' in el.dataset) toggleMobileMenu();
    });
});

document.querySelector('[data-add-contributor]')?.addEventListener('click', () => {
    showSection('blog-editor');
    const editType = document.getElementById('edit-type');
    if (editType) editType.value = 'contributor';
    toggleEditorFields();
});

document.querySelector('[data-remove-image]')?.addEventListener('click', removeSelectedImage);
document.getElementById('btn-run-mock')?.addEventListener('click', runMockScan);
document.getElementById('rule-filter')?.addEventListener('change', renderRules);
document.getElementById('rule-search')?.addEventListener('input', renderRules);
document.getElementById('edit-type')?.addEventListener('change', toggleEditorFields);
