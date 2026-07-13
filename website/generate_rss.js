const path = require('path');

/**
 * OpenShield RSS Generator (Node.js)
 * Designed for Vercel Build Step
 */

function generateRSS() {
    try {
        const siteContent = require(path.join(__dirname, 'content.js'));

        let rssItems = '';

        siteContent.blog.forEach(post => {
            rssItems += `
        <item>
            <title><![CDATA[${post.title}]]></title>
            <link>https://openshield.org/#blog/${post.id}</link>
            <guid>https://openshield.org/#blog/${post.id}</guid>
            <pubDate>${new Date(post.date).toUTCString()}</pubDate>
            <description><![CDATA[${post.excerpt}]]></description>
            <author>${post.author}</author>
        </item>`;
        });

        const rssFeed = `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title>OpenShield Blog</title>
    <link>https://openshield.org</link>
    <description>Enterprise-Grade Open Source CSPM Project Updates</description>
    <language>en-us</language>
    <atom:link href="https://openshield.org/feed.xml" rel="self" type="application/rss+xml" />
    ${rssItems}
</channel>
</rss>`;

        fs.writeFileSync(path.join(__dirname, 'feed.xml'), rssFeed);
        console.log("✅ Successfully generated website/feed.xml");

    } catch (error) {
        console.error("❌ Error generating RSS:", error.message);
    }
}

generateRSS();
