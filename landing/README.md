# ELYRA Landing Page

This directory is a dependency-free static landing page for ELYRA / Elyra Antivirus. It is ready to deploy from its own directory to Netlify or Vercel; no build step, framework runtime, analytics, form endpoint, or cloud service is used.

The page detects Windows and Linux from the browser, preselects the matching release asset, and always keeps a visible package selector as a fallback. It does not collect or transmit endpoint telemetry.

## Release-link configuration

Before a public deployment, first upload both signed/checked release artifacts to a GitHub Release. Then edit only [`assets/js/download-config.js`](assets/js/download-config.js):

1. Set `version` and `releaseTag` to the published GitHub Release tag.
2. Set each `filename` to the exact uploaded asset name.
3. Keep the derived `url` values pointing to the matching `releases/download/<tag>/<asset>` URLs.
4. Verify both URLs in a private/incognito browser and publish checksums alongside the assets.

The committed values are versioned release-asset placeholders so the download routing is reproducible once those assets are published. They do **not** assert that a GitHub Release or installer already exists.

## Local preview and checks

From this `landing/` directory:

```powershell
python -m http.server 8080
```

Open `http://localhost:8080`. Confirm the auto-detected platform, manually switch the selector, use keyboard navigation, and verify that the configured release asset URL changes as expected.

If Node.js is installed, syntax-check the JavaScript without installing packages:

```powershell
node --check assets/js/download-config.js
node --check assets/js/app.js
```

## Netlify deployment

1. Push this repository to GitHub after release URLs are configured.
2. In Netlify, choose **Add new site → Import an existing project**.
3. Select the repository and set **Base directory** to `landing`.
4. Leave the build command empty and set **Publish directory** to `.`.
5. Deploy. `netlify.toml` supplies static security headers.

For the Netlify CLI, run this from `landing/` after signing in:

```powershell
netlify deploy --prod --dir .
```

## Vercel deployment

1. Import the repository in Vercel.
2. Set **Root Directory** to `landing`.
3. Select the **Other** framework preset; no build command is required.
4. Deploy. `vercel.json` applies the same static security headers.

For the Vercel CLI, run this from the repository root:

```powershell
vercel --cwd landing --prod
```

## Deployment safeguards

- Use HTTPS only for package links; the client-side code deliberately rejects non-HTTPS configured downloads.
- Publish SHA-256 checksums and package signatures with every release.
- Keep the landing page separate from the local security engine. This site is an installer-discovery surface, not an endpoint management console.
- Do not add remote logging, tracking pixels, analytics, or central-control functions without an explicit product and privacy review.
