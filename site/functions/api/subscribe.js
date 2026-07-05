// Cloudflare Pages Function — POST /api/subscribe
// Proxies to Buttondown's public embed-subscribe endpoint (no API key
// required) and returns a clean JSON result to the front-end form. Running
// it server-side (vs. posting from the browser) avoids CORS and lets us
// read the real response instead of an opaque one.
//
// To point at a different Buttondown account, change BUTTONDOWN_USERNAME
// (or set it as an env var on the Pages project).

const DEFAULT_USERNAME = 'eunolabs';

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

export async function onRequestPost({ request, env }) {
  const username = (env && env.BUTTONDOWN_USERNAME) || DEFAULT_USERNAME;

  let email;
  try {
    const body = await request.json();
    email = (body && body.email ? String(body.email) : '').trim();
  } catch (_) {
    return json(400, { ok: false, error: 'Invalid request.' });
  }

  if (!email || email.indexOf('@') === -1 || email.length > 254) {
    return json(400, { ok: false, error: 'Please enter a valid email.' });
  }

  const form = new URLSearchParams();
  form.set('email', email);
  form.set('tag', 'waitlist');

  // Network, DNS, TLS, or connection failures must surface as the clean 502
  // JSON contract below, not as an unhandled rejection that Cloudflare turns
  // into an opaque platform error. A bounded timeout keeps a hung upstream from
  // holding the request open indefinitely.
  let res;
  try {
    res = await fetch(
      `https://buttondown.com/api/emails/embed-subscribe/${encodeURIComponent(username)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
        redirect: 'manual',
        signal: AbortSignal.timeout(8000),
      }
    );
  } catch (_) {
    return json(502, { ok: false, error: 'Could not sign you up — try again.' });
  }

  // Buttondown answers a successful subscribe with a redirect (3xx) to its
  // confirmation page, or a 200. Anything < 400 means it was accepted.
  if (res.status < 400) return json(200, { ok: true });
  return json(502, { ok: false, error: 'Could not sign you up — try again.' });
}

// Reject non-POST methods cleanly.
export async function onRequest({ request }) {
  if (request.method === 'POST') return; // handled by onRequestPost
  return json(405, { ok: false, error: 'Method not allowed.' });
}
