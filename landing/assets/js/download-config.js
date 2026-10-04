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
  const version = "1.0.8";
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
      ai: Object.freeze({
        label: "Elyra AI Assistant Debian package",
        filename: `elyra-ai-linux_${version}-1_amd64.deb`,
        url: `${releaseBaseUrl}/elyra-ai-linux_${version}-1_amd64.deb`,
      }),
      windowsAi: Object.freeze({
        label: "Elyra AI Assistant Windows installer",
        filename: `ELYRA-AI-Setup-${version}-x64.exe`,
        url: `${releaseBaseUrl}/ELYRA-AI-Setup-${version}-x64.exe`,
      }),
    }),
  });
})(window);
