(function initialiseLandingPage() {
  "use strict";

  const config = window.ELLIOT_DOWNLOAD_CONFIG;
  const supportedPlatforms = new Set(["windows", "linux"]);
  const platformSelect = document.querySelector("#platform-select");
  const downloadSection = document.querySelector("#download");
  const downloadLinks = document.querySelectorAll("[data-download-link]");
  const downloadLabels = document.querySelectorAll("[data-download-label]");
  const summaries = document.querySelectorAll("[data-platform-summary], [data-download-status]");
  const releaseLinks = document.querySelectorAll("[data-release-link]");
  const releaseVersions = document.querySelectorAll("[data-release-version]");
  const platformCards = document.querySelectorAll("[data-platform-card]");
  const platformCurrentLabels = document.querySelectorAll("[data-platform-current]");
  const autoDetectButton = document.querySelector("[data-auto-detect]");
  const storageKey = "elliot-download-platform";

  if (!config || !platformSelect) {
    return;
  }

  function isSafeHttpsUrl(value) {
    try {
      return new URL(value).protocol === "https:";
    } catch {
      return false;
    }
  }

  function detectPlatform() {
    const userAgentDataPlatform = navigator.userAgentData && navigator.userAgentData.platform;
    const hints = [
      userAgentDataPlatform,
      navigator.platform,
      navigator.userAgent,
    ].filter(Boolean).join(" ").toLowerCase();

    if (/android|iphone|ipad|ipod|mac os|macintosh/.test(hints)) {
      return "unsupported";
    }
    if (/win/.test(hints)) {
      return "windows";
    }
    if (/linux|x11|unix/.test(hints)) {
      return "linux";
    }
    return "unknown";
  }

  function readSavedPlatform() {
    try {
      const saved = window.localStorage.getItem(storageKey);
      return supportedPlatforms.has(saved) ? saved : null;
    } catch {
      return null;
    }
  }

  function savePlatform(platform) {
    try {
      if (supportedPlatforms.has(platform)) {
        window.localStorage.setItem(storageKey, platform);
      } else {
        window.localStorage.removeItem(storageKey);
      }
    } catch {
      // Private browsing and restrictive browser policies can disable storage.
    }
  }

  function messageFor(platform, source) {
    if (platform === "windows") {
      return source === "detected"
        ? "Windows detected. Your download is ready."
        : "Windows selected. Your download is ready.";
    }
    if (platform === "linux") {
      return source === "detected"
        ? "Linux detected. Your Debian/Pardus package is ready."
        : "Linux / Pardus selected. Your package is ready.";
    }
    if (platform === "unsupported") {
      return "This browser appears to be on an unsupported platform. Choose a Windows or Linux package below.";
    }
    return "We could not identify your operating system. Choose a Windows or Linux package below.";
  }

  function updatePlatformCards(platform) {
    platformCards.forEach((card) => {
      const active = card.dataset.platformCard === platform;
      card.classList.toggle("is-active", active);
      card.setAttribute("aria-current", active ? "true" : "false");
    });
    platformCurrentLabels.forEach((label) => {
      const active = label.dataset.platformCurrent === platform;
      label.textContent = active ? "Selected for download" : "Available for selection";
    });
  }

  function updateDownloadTarget(platform, source) {
    const packageInfo = config.downloads[platform];
    const available = Boolean(packageInfo && isSafeHttpsUrl(packageInfo.url));
    const fallbackUrl = isSafeHttpsUrl(config.releasePageUrl)
      ? config.releasePageUrl
      : "https://github.com/mustafaoyan/Siper-Antivirus/releases";
    const label = available ? `Download for ${packageInfo.label}` : "Choose your download";
    const href = available ? packageInfo.url : "#download";

    document.documentElement.dataset.selectedPlatform = available ? platform : "unknown";
    platformSelect.value = available ? platform : "unknown";
    downloadLabels.forEach((element) => { element.textContent = label; });
    summaries.forEach((element) => { element.textContent = messageFor(platform, source); });
    updatePlatformCards(available ? platform : "unknown");

    downloadLinks.forEach((link) => {
      link.href = href;
      link.dataset.downloadPlatform = available ? platform : "";
      link.removeAttribute("download");
      link.setAttribute("aria-label", available ? `${label}: ${packageInfo.filename}` : "Choose a download platform");
    });

    releaseLinks.forEach((link) => { link.href = fallbackUrl; });
  }

  function focusDownloadSelector(event) {
    if (supportedPlatforms.has(platformSelect.value)) {
      return;
    }
    event.preventDefault();
    downloadSection.scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(() => platformSelect.focus({ preventScroll: true }), 350);
  }

  const detectedPlatform = detectPlatform();
  const initiallySelected = readSavedPlatform() || detectedPlatform;
  updateDownloadTarget(initiallySelected, readSavedPlatform() ? "saved" : "detected");

  releaseVersions.forEach((element) => {
    element.textContent = `${config.releaseTag} (${config.version})`;
  });

  const yearElement = document.querySelector("[data-current-year]");
  if (yearElement) {
    yearElement.textContent = String(new Date().getFullYear());
  }

  platformSelect.addEventListener("change", () => {
    const selected = supportedPlatforms.has(platformSelect.value) ? platformSelect.value : "unknown";
    savePlatform(selected);
    updateDownloadTarget(selected, "selected");
  });

  downloadLinks.forEach((link) => link.addEventListener("click", focusDownloadSelector));

  if (autoDetectButton) {
    autoDetectButton.addEventListener("click", () => {
      savePlatform("unknown");
      updateDownloadTarget(detectedPlatform, "detected");
      platformSelect.focus();
    });
  }
})();
