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
  const version = "1.0.2";
  const releaseTag = `v${version}`;
  const releaseBaseUrl = `https://github.com/${repository}/releases/download/${releaseTag}`;

  global.ELYRA_DOWNLOAD_CONFIG = Object.freeze({
    version,
    releaseTag,
    published: true,
    releasePageUrl: `https://github.com/${repository}/releases`,
    downloads: Object.freeze({
      linux: Object.freeze({
        label: "Linux / Pardus (64-bit .deb)",
        filename: `elyra-pardus_${version}-1_amd64.deb`,
        url: `${releaseBaseUrl}/elyra-pardus_${version}-1_amd64.deb`,
      }),
    }),
  });
})(window);
