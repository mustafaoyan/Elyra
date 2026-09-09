/*
 * Release configuration for the public landing page.
 *
 * Before publishing the site, publish the matching files in a GitHub Release,
 * then update only the version/tag and asset filenames below. These are
 * versioned release-asset URL templates, not a claim that the assets already
 * exist at the time this source is committed.
 */
(function configureElliotDownloads(global) {
  "use strict";

  const repository = "mustafaoyan/Siper-Antivirus";
  const version = "1.0.0";
  const releaseTag = `v${version}`;
  const releaseBaseUrl = `https://github.com/${repository}/releases/download/${releaseTag}`;

  global.ELLIOT_DOWNLOAD_CONFIG = Object.freeze({
    version,
    releaseTag,
    releasePageUrl: `https://github.com/${repository}/releases`,
    downloads: Object.freeze({
      windows: Object.freeze({
        label: "Windows (64-bit)",
        filename: `ELLIOT-Setup-${version}-x64.exe`,
        url: `${releaseBaseUrl}/ELLIOT-Setup-${version}-x64.exe`,
      }),
      linux: Object.freeze({
        label: "Linux / Pardus (64-bit .deb)",
        filename: `elliot_${version}_amd64.deb`,
        url: `${releaseBaseUrl}/elliot_${version}_amd64.deb`,
      }),
    }),
  });
})(window);
