(function () {
  'use strict';

  // Resolve the public root from this script's own URL — works with file://
  var s = document.currentScript || (function () {
    var all = document.getElementsByTagName('script');
    for (var i = all.length - 1; i >= 0; i--)
      if (all[i].src && all[i].src.indexOf('components.js') !== -1) return all[i];
  }());
  var root = s ? s.src.replace(/\/components\.js.*$/, '') : '.';

  var GITHUB = 'https://github.com/eunolabs/eunox';

  var GITHUB_SVG =
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">' +
      '<path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217' +
      '.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11' +
      '-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53' +
      ' 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1' +
      '.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.5' +
      '64 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.37' +
      '9.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309' +
      '.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22' +
      ' 12.017C22 6.484 17.522 2 12 2z"/>' +
    '</svg>';

  var onBlog = window.location.pathname.indexOf('/blog') !== -1;
  var onQuickstart = window.location.pathname.indexOf('/quickstart') !== -1;

  // ── Header ──────────────────────────────────────────────────────────
  var headerEl = document.getElementById('site-header');
  if (headerEl) {
    headerEl.outerHTML =
      '<header class="site-header">' +
        '<div class="header-left">' +
          '<a class="logo" href="' + root + '/index.html">' +
            '<img src="' + root + '/eunolabs.png" alt="eunolabs" />' +
            '<span class="wordmark">eunolabs.ai</span>' +
          '</a>' +
          '<span class="stage-badge">Coming Soon</span>' +
        '</div>' +
        '<nav class="header-nav" aria-label="Primary">' +
          '<a href="' + root + '/quickstart/index.html" class="nav-link' + (onQuickstart ? ' active' : '') + '">Quickstart</a>' +
          '<a href="' + root + '/blog/index.html" class="nav-link' + (onBlog ? ' active' : '') + '">Blog</a>' +
          '<a href="' + GITHUB + '" target="_blank" rel="noopener noreferrer" class="btn-github">' +
            GITHUB_SVG + ' GitHub' +
          '</a>' +
        '</nav>' +
      '</header>';
  }

  // ── Footer ──────────────────────────────────────────────────────────
  var footerEl = document.getElementById('site-footer');
  if (footerEl) {
    footerEl.outerHTML =
      '<footer class="site-footer">' +
        '<div class="footer-grid">' +
          '<div class="footer-col footer-brand">' +
            '<a class="logo" href="' + root + '/index.html">' +
              '<img src="' + root + '/eunolabs.png" alt="eunolabs" style="height:30px" />' +
              '<span class="wordmark">eunolabs.ai</span>' +
            '</a>' +
            '<p>Policy-native enforcement for AI agents. One YAML file. Zero infrastructure. No telemetry.</p>' +
            '<span class="footer-license">Apache-2.0</span>' +
          '</div>' +
          '<div class="footer-col">' +
            '<h5>Resources</h5>' +
            '<ul>' +
              '<li><a href="https://modelcontextprotocol.io/specification" target="_blank" rel="noopener noreferrer">MCP spec</a></li>' +
              '<li style="display:none"><a href="' + GITHUB + '" target="_blank" rel="noopener noreferrer">eunox README</a></li>' +
              '<li><a href="https://github.com/eunolabs/mcp-capability-manifest" target="_blank" rel="noopener noreferrer">MCP Capability Manifest</a></li>' +
            '</ul>' +
          '</div>' +
          '<div class="footer-col">' +
            '<h5>Project</h5>' +
            '<ul>' +
              '<li><a href="' + GITHUB + '" target="_blank" rel="noopener noreferrer">GitHub</a></li>' +
              '<li style="display:none"><a href="' + GITHUB + '/issues" target="_blank" rel="noopener noreferrer">Issues</a></li>' +
              '<li style="display:none"><a href="' + GITHUB + '/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">License</a></li>' +
            '</ul>' +
          '</div>' +
          '<div class="footer-col">' +
            '<h5>Contact</h5>' +
            '<ul>' +
              '<li><a href="mailto:hello@eunolabs.ai">hello@eunolabs.ai</a></li>' +
              '<li><a href="' + GITHUB + '/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer">Security</a></li>' +
            '</ul>' +
          '</div>' +
        '</div>' +
        '<div class="footer-bottom">' +
          '<span>&copy; 2026 eunox &middot; An ' +
            '<a href="https://github.com/eunolabs" target="_blank" rel="noopener noreferrer">eunolabs.ai</a>' +
          ' project &middot; Patent Pending</span>' +
          '<span>Built for the Model Context Protocol</span>' +
        '</div>' +
      '</footer>';
  }

  // ── Giscus comments + reactions ─────────────────────────────────────
  // Backed by GitHub Discussions in a dedicated comments repo, so reader
  // threads stay out of the main code repo. Only mounts where a
  // #giscus-thread placeholder exists (i.e. individual blog posts).
  //
  // SETUP (one time): create the repo below, enable Discussions, install
  // the giscus GitHub App (https://github.com/apps/giscus) on it, add a
  // Discussions category, then read the four values off https://giscus.app
  // and paste repoId + categoryId here. Until both IDs are filled in,
  // the widget is skipped so nothing broken ships.
  var GISCUS = {
    repo:       'eunolabs/eunox-discuss',
    repoId:     'R_kgDOSxl-CA',
    category:   'Comments',
    categoryId: 'DIC_kwDOSxl-CM4C-ilL',
    theme:      'preferred_color_scheme'
  };

  // Giscus needs a real http(s) origin (GitHub OAuth + postMessage); under
  // file:// the origin is null and the iframe is refused, so skip it there.
  var thread = document.getElementById('giscus-thread');
  if (thread &&
      window.location.protocol !== 'file:' &&
      GISCUS.repoId.indexOf('PASTE_') !== 0 &&
      GISCUS.categoryId.indexOf('PASTE_') !== 0) {
    var g = document.createElement('script');
    g.src = 'https://giscus.app/client.js';
    g.async = true;
    g.crossOrigin = 'anonymous';
    g.setAttribute('data-repo', GISCUS.repo);
    g.setAttribute('data-repo-id', GISCUS.repoId);
    g.setAttribute('data-category', GISCUS.category);
    g.setAttribute('data-category-id', GISCUS.categoryId);
    g.setAttribute('data-mapping', 'pathname');
    g.setAttribute('data-strict', '1');
    g.setAttribute('data-reactions-enabled', '1');
    g.setAttribute('data-emit-metadata', '0');
    g.setAttribute('data-input-position', 'bottom');
    g.setAttribute('data-theme', GISCUS.theme);
    g.setAttribute('data-lang', 'en');
    g.setAttribute('data-loading', 'lazy');
    thread.appendChild(g);
  }
}());
