/*
 * Release configuration for the public landing page.
 *
 * Before publishing the site, publish the matching Linux file in a GitHub Release,
 * then update only the version/tag and asset filenames below. These are
 * versioned release-asset URL templates, not a claim that the assets already
 * exist at the time this source is committed.
 */
(function configureElyraDownloads(global) {
  "use strict";

  const repository = "mustafaoyan/Elyra";
  const version = "1.0.3";
  const releaseTag = `v${version}`;
  const releaseBaseUrl = `https://github.com/${repository}/releases/download/${releaseTag}`;

  global.ELYRA_DOWNLOAD_CONFIG = Object.freeze({
    version,
    releaseTag,
    published: true,
    releasePageUrl: `https://github.com/${repository}/releases`,
    downloads: Object.freeze({
      linux: Object.freeze({
        label: "Linux x86_64 portable bundle",
        filename: `elyra-linux-${version}-x86_64.tar.gz`,
        url: `${releaseBaseUrl}/elyra-linux-${version}-x86_64.tar.gz`,
      }),
    }),
  });
})(window);
