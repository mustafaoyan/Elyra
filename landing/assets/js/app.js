(function initialiseLandingPage() {
  "use strict";

  const config = window.ELYRA_DOWNLOAD_CONFIG;
  const supportedPlatforms = new Set(["linux"]);
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
  const aiDownloadLinks = document.querySelectorAll("[data-ai-download-link]");
  const windowsAiDownloadLinks = document.querySelectorAll("[data-windows-ai-download-link]");
  const storageKey = "elyra-download-platform";

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
    if (platform === "linux") {
      return source === "detected"
        ? "Linux algılandı. Taşınabilir x86_64 paket hazır."
        : "Linux seçildi. Taşınabilir paket hazır.";
    }
    if (platform === "windows") {
      return "Windows sÃ¼rÃ¼mÃ¼ hazÄ±rlanÄ±yor. Linux/Pardus paketi ÅŸu anda aktif.";
    }
    if (platform === "unsupported") {
      return "Bu tarayıcı desteklenmeyen bir platformda görünüyor. Linux paketini seçin.";
    }
    return "İşletim sistemi algılanamadı. Linux paketini seçin.";
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
    const available = Boolean(config.published && packageInfo && isSafeHttpsUrl(packageInfo.url));
    const fallbackUrl = isSafeHttpsUrl(config.releasePageUrl)
      ? config.releasePageUrl
      : "https://github.com/mustafaoyan/Elyra/releases";
    const label = available ? "Linux paketini indir" : "Linux paketi henüz yayınlanmadı";
    const href = available ? packageInfo.url : fallbackUrl;

    document.documentElement.dataset.selectedPlatform = available ? platform : "unknown";
    platformSelect.value = available ? platform : "unknown";
    downloadLabels.forEach((element) => { element.textContent = label; });
    summaries.forEach((element) => {
      element.textContent = available ? messageFor(platform, source) : "Linux paketi release sayfasında yayınlandığında burada indirilebilir olacak.";
    });
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

  const aiPackage = config.downloads.ai;
  if (aiPackage && isSafeHttpsUrl(aiPackage.url)) {
    aiDownloadLinks.forEach((link) => {
      link.href = aiPackage.url;
      link.classList.remove("download-option--disabled");
      link.removeAttribute("aria-disabled");
      link.querySelector(".download-option__badge")?.replaceChildren("DEB İNDİR");
      link.querySelector("small")?.replaceChildren("Yerel AI analiz asistanını kur");
    });
  }
  const windowsAiPackage = config.downloads.windowsAi;
  if (windowsAiPackage && isSafeHttpsUrl(windowsAiPackage.url)) {
    windowsAiDownloadLinks.forEach((link) => { link.href = windowsAiPackage.url; });
  }

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

  document.querySelectorAll('a[href="#download"]').forEach((trigger) => {
    trigger.addEventListener("click", () => {
      downloadSection.classList.remove("is-open");
      window.setTimeout(() => downloadSection.classList.add("is-open"), 20);
    });
  });

  document.querySelectorAll('.download-option--disabled[href]').forEach((link) => {
    link.addEventListener("click", (event) => event.preventDefault());
  });
})();
