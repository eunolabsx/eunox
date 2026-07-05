# eunox website

The public-facing website for [eunolabs.ai](https://eunolabs.ai) — a plain
static HTML site with no framework. `public/` is the full authoring tree; the
deploy workflow copies it verbatim into `site/dist/`, which is what ships to
Cloudflare Pages (there is no framework build — see Deployment below).

## Layout

```
public/                  The complete static site, served at the root
├── index.html           Landing page
├── quickstart/          Quick-start guide          → /quickstart
├── features/            Full condition matrix       → /features
├── how-it-works/        Architecture & request flow → /how-it-works
├── policies/            Reference policies          → /policies
├── docs/                Documentation hub           → /docs
├── deploy/              Deploy guide                → /deploy
├── blog/
│   ├── index.html       Blog listing (newest first) → /blog
│   └── <slug>/          Individual blog post        → /blog/<slug>
├── eunolabs.png         Logo assets
├── styles.css           Shared styles (dark hero + light content)
└── main.js              Terminal animation, copy-button, smooth scroll
```

Each page is a directory containing an `index.html`, which gives clean URLs
(e.g. `/quickstart` is served from `public/quickstart/index.html`).

A root-level `_redirects` file 301-redirects the `.html` form of each section
(e.g. `/quickstart.html` → `/quickstart`) to its clean URL, so typed-in
extensions, old bookmarks, and external links resolve. Cloudflare Pages reads
it from the deploy root (it ships because the assemble step copies all of
`public/`).

## Local preview

The pages use root-absolute paths (`/styles.css`, `/blog/…`), so serve the
`public/` directory over HTTP rather than opening files directly:

```bash
cd public && python3 -m http.server 4321
# open http://localhost:4321/
```

Any static file server works (`npx serve public`, `php -S`, etc.).

## Editing content

Edit the `.html` files directly. The header and footer are duplicated in each
page; update them consistently across pages when changing navigation. Shared
styling lives in `public/styles.css`.

## Deployment

Pushed to Cloudflare Pages by `.github/workflows/deploy-site.yml`, which
assembles the entire `public/` tree into `site/dist/` and deploys that (no
framework build). `site/functions/` is served as Pages Functions. See
`wrangler.toml` for project config.

## License

Apache-2.0, same as the rest of the eunox open-source project.
