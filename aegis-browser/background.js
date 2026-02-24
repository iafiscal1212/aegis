/**
 * AEGIS Browser Guardian — Background Service Worker
 *
 * Handles:
 * - Download interception and verification
 * - Domain blocklist management
 * - Native messaging with AEGIS CLI
 * - Statistics tracking
 * - Scareware page alerts from content scripts
 */

// ─── State ───────────────────────────────────────────────────────────────────

const NATIVE_HOST = "com.aegis.browser_guardian";
let nativePort = null;
let stats = { blocked: 0, warned: 0, downloads_checked: 0, scareware_detected: 0 };
let blocklist = { malvertising: [], scareware: [], fake_software: [], crypto_scam: [], phishing_patterns: [] };
let officialSites = {};
let settings = {
  enabled: true,
  block_malvertising: true,
  block_scareware: true,
  check_downloads: true,
  verify_software_urls: true,
  native_messaging: false,
  notifications: true,
};

// ─── Initialization ──────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    await chrome.storage.local.set({ settings, stats });
    console.log("[AEGIS] Extension installed. Loading rules...");
  }
  await loadRules();
});

chrome.runtime.onStartup.addListener(async () => {
  await loadState();
  await loadRules();
});

async function loadState() {
  const data = await chrome.storage.local.get(["settings", "stats"]);
  if (data.settings) settings = { ...settings, ...data.settings };
  if (data.stats) stats = { ...stats, ...data.stats };
}

async function loadRules() {
  try {
    const resp = await fetch(chrome.runtime.getURL("rules/blocklist.json"));
    blocklist = await resp.json();

    const resp2 = await fetch(chrome.runtime.getURL("rules/official_sites.json"));
    officialSites = await resp2.json();

    console.log(`[AEGIS] Loaded ${Object.values(blocklist).flat().length} blocklist entries`);
  } catch (e) {
    console.error("[AEGIS] Failed to load rules:", e);
  }
}

// ─── Download Interception ───────────────────────────────────────────────────

chrome.downloads.onCreated.addListener(async (item) => {
  if (!settings.enabled || !settings.check_downloads) return;

  stats.downloads_checked++;
  const url = item.finalUrl || item.url || "";
  const filename = item.filename || "";

  const result = analyzeDownload(url, filename);

  if (result.action === "block") {
    chrome.downloads.cancel(item.id);
    stats.blocked++;
    await saveStats();
    logEvent("download_blocked", { url, filename, reason: result.reason });

    if (settings.notifications) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "AEGIS — Download Blocked",
        message: result.reason,
        priority: 2,
      });
    }
  } else if (result.action === "warn") {
    stats.warned++;
    await saveStats();
    logEvent("download_warned", { url, filename, reason: result.reason });

    if (settings.notifications) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "AEGIS — Download Warning",
        message: result.reason,
        priority: 1,
      });
    }
  }
});

function analyzeDownload(url, filename) {
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    return { action: "allow", reason: "" };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const lowerFile = filename.toLowerCase();

  // Check blocklist domains
  const allBlocked = [
    ...blocklist.malvertising,
    ...blocklist.scareware,
    ...blocklist.fake_software,
    ...blocklist.crypto_scam,
  ];

  for (const domain of allBlocked) {
    if (hostname === domain || hostname.endsWith("." + domain)) {
      return { action: "block", reason: `Download from blocked domain: ${domain}` };
    }
  }

  // Check for dangerous file types from non-verified sources
  const dangerousExts = [".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com", ".pif", ".reg"];
  const isDangerous = dangerousExts.some((ext) => lowerFile.endsWith(ext));

  if (isDangerous && settings.verify_software_urls) {
    const isOfficial = checkOfficialSource(hostname);
    if (!isOfficial) {
      return {
        action: "warn",
        reason: `Executable download from unverified source: ${hostname}. Verify this is the official website.`,
      };
    }
  }

  // Check for double extensions (invoice.pdf.exe)
  const parts = lowerFile.split(".");
  if (parts.length >= 3) {
    const lastExt = "." + parts[parts.length - 1];
    const secondLast = "." + parts[parts.length - 2];
    const docExts = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"];
    if (dangerousExts.includes(lastExt) && docExts.includes(secondLast)) {
      return {
        action: "block",
        reason: `Suspicious double extension detected: ${filename}. This is a common malware trick.`,
      };
    }
  }

  return { action: "allow", reason: "" };
}

function checkOfficialSource(hostname) {
  // Remove www. prefix
  const clean = hostname.replace(/^www\./, "");

  for (const [, domains] of Object.entries(officialSites)) {
    if (typeof domains === "string") continue; // skip _comment
    for (const domain of domains) {
      if (clean === domain || clean.endsWith("." + domain)) {
        return true;
      }
    }
  }

  // Also allow well-known hosting platforms
  const trustedHosts = [
    "github.com",
    "github.io",
    "githubusercontent.com",
    "gitlab.com",
    "sourceforge.net",
    "npmjs.com",
    "pypi.org",
    "crates.io",
    "microsoft.com",
    "apple.com",
    "google.com",
    "amazonaws.com",
    "cloudfront.net",
    "azureedge.net",
  ];

  return trustedHosts.some((h) => clean === h || clean.endsWith("." + h));
}

// ─── URL Navigation Check ────────────────────────────────────────────────────

chrome.webNavigation.onBeforeNavigate.addListener(
  async (details) => {
    if (!settings.enabled || details.frameId !== 0) return;

    let urlObj;
    try {
      urlObj = new URL(details.url);
    } catch {
      return;
    }

    const hostname = urlObj.hostname.toLowerCase();

    // Check phishing patterns in hostname
    if (settings.block_scareware) {
      for (const pattern of blocklist.phishing_patterns || []) {
        if (hostname.includes(pattern)) {
          stats.blocked++;
          await saveStats();
          logEvent("phishing_blocked", { url: details.url, pattern });
          // Redirect to warning page
          chrome.tabs.update(details.tabId, {
            url: chrome.runtime.getURL(
              `popup/blocked.html?reason=${encodeURIComponent("Phishing pattern detected: " + pattern)}&url=${encodeURIComponent(details.url)}`
            ),
          });
          return;
        }
      }
    }
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// ─── Messages from Content Scripts ───────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "scareware_detected") {
    stats.scareware_detected++;
    saveStats();
    logEvent("scareware_detected", {
      url: sender.tab?.url,
      indicators: message.indicators,
    });

    if (settings.notifications) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "AEGIS — Scareware Detected",
        message: `This page appears to be a scareware/fake alert page. ${message.indicators.length} indicators found.`,
        priority: 2,
      });
    }

    sendResponse({ action: "overlay" });
    return true;
  }

  if (message.type === "get_stats") {
    sendResponse(stats);
    return true;
  }

  if (message.type === "get_settings") {
    sendResponse(settings);
    return true;
  }

  if (message.type === "update_settings") {
    settings = { ...settings, ...message.settings };
    chrome.storage.local.set({ settings });
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "check_url") {
    const result = checkUrl(message.url);
    sendResponse(result);
    return true;
  }

  if (message.type === "native_query") {
    queryNativeHost(message.payload).then(sendResponse);
    return true;
  }
});

function checkUrl(url) {
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch {
    return { safe: true, reason: "" };
  }

  const hostname = urlObj.hostname.toLowerCase();

  const allBlocked = [
    ...blocklist.malvertising,
    ...blocklist.scareware,
    ...blocklist.fake_software,
    ...blocklist.crypto_scam,
  ];

  for (const domain of allBlocked) {
    if (hostname === domain || hostname.endsWith("." + domain)) {
      return { safe: false, reason: `Blocked domain: ${domain}`, category: "blocklist" };
    }
  }

  for (const pattern of blocklist.phishing_patterns || []) {
    if (hostname.includes(pattern)) {
      return { safe: false, reason: `Phishing pattern: ${pattern}`, category: "phishing" };
    }
  }

  return { safe: true, reason: "" };
}

// ─── Native Messaging ────────────────────────────────────────────────────────

async function queryNativeHost(payload) {
  if (!settings.native_messaging) {
    return { error: "Native messaging disabled" };
  }

  return new Promise((resolve) => {
    try {
      if (!nativePort) {
        nativePort = chrome.runtime.connectNative(NATIVE_HOST);
        nativePort.onDisconnect.addListener(() => {
          nativePort = null;
        });
      }

      const listener = (response) => {
        nativePort.onMessage.removeListener(listener);
        resolve(response);
      };

      nativePort.onMessage.addListener(listener);
      nativePort.postMessage(payload);

      // Timeout after 5 seconds
      setTimeout(() => {
        resolve({ error: "Native host timeout" });
      }, 5000);
    } catch (e) {
      resolve({ error: `Native messaging error: ${e.message}` });
    }
  });
}

// ─── Event Log ───────────────────────────────────────────────────────────────

async function logEvent(type, data) {
  const log = (await chrome.storage.local.get("eventLog"))?.eventLog || [];
  log.unshift({
    type,
    data,
    timestamp: new Date().toISOString(),
  });

  // Keep last 500 events
  if (log.length > 500) log.length = 500;
  await chrome.storage.local.set({ eventLog: log });
}

async function saveStats() {
  await chrome.storage.local.set({ stats });
}

// ─── Badge Update ────────────────────────────────────────────────────────────

chrome.alarms.create("updateBadge", { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "updateBadge") {
    const total = stats.blocked + stats.scareware_detected;
    if (total > 0) {
      chrome.action.setBadgeText({ text: String(total) });
      chrome.action.setBadgeBackgroundColor({ color: "#EF4444" });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  }
});

// Initial load
loadState().then(loadRules);
