/**
 * AEGIS Browser Guardian — Popup Script
 */

document.addEventListener("DOMContentLoaded", async () => {
  // ─── Load current settings and stats ────────────────────────────────────

  const settings = await sendMessage({ type: "get_settings" });
  const stats = await sendMessage({ type: "get_stats" });

  // ─── Populate stats ─────────────────────────────────────────────────────

  if (stats) {
    document.getElementById("stat-blocked").textContent = stats.blocked || 0;
    document.getElementById("stat-warned").textContent = stats.warned || 0;
    document.getElementById("stat-downloads").textContent = stats.downloads_checked || 0;
    document.getElementById("stat-scareware").textContent = stats.scareware_detected || 0;
  }

  // ─── Populate settings toggles ──────────────────────────────────────────

  if (settings) {
    setToggle("toggle-enabled", settings.enabled);
    setToggle("toggle-malvertising", settings.block_malvertising);
    setToggle("toggle-scareware", settings.block_scareware);
    setToggle("toggle-downloads", settings.check_downloads);
    setToggle("toggle-verify", settings.verify_software_urls);
    setToggle("toggle-notifications", settings.notifications);

    if (!settings.enabled) {
      document.body.classList.add("disabled");
    }
  }

  // ─── Check current tab status ───────────────────────────────────────────

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const url = new URL(tab.url);
      document.getElementById("status-domain").textContent = url.hostname;

      const result = await sendMessage({ type: "check_url", url: tab.url });
      if (result && !result.safe) {
        setPageStatus("danger", result.reason);
      } else {
        setPageStatus("safe", "Page is safe");
      }
    } else {
      document.getElementById("status-domain").textContent = "N/A";
    }
  } catch {
    document.getElementById("status-domain").textContent = "N/A";
  }

  // ─── Toggle event handlers ──────────────────────────────────────────────

  document.getElementById("toggle-enabled").addEventListener("change", async (e) => {
    const enabled = e.target.checked;
    document.body.classList.toggle("disabled", !enabled);
    await updateSetting("enabled", enabled);
  });

  const settingMap = {
    "toggle-malvertising": "block_malvertising",
    "toggle-scareware": "block_scareware",
    "toggle-downloads": "check_downloads",
    "toggle-verify": "verify_software_urls",
    "toggle-notifications": "notifications",
  };

  for (const [id, key] of Object.entries(settingMap)) {
    document.getElementById(id).addEventListener("change", async (e) => {
      await updateSetting(key, e.target.checked);
    });
  }

  // ─── URL Check ──────────────────────────────────────────────────────────

  document.getElementById("url-check-btn").addEventListener("click", checkUrl);
  document.getElementById("url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") checkUrl();
  });

  async function checkUrl() {
    let url = document.getElementById("url-input").value.trim();
    if (!url) return;

    // Add protocol if missing
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }

    const resultEl = document.getElementById("url-result");
    resultEl.style.display = "block";
    resultEl.className = "url-result";
    resultEl.textContent = "Checking...";

    const result = await sendMessage({ type: "check_url", url });

    if (result && !result.safe) {
      resultEl.className = "url-result danger";
      resultEl.textContent = result.reason;
    } else {
      resultEl.className = "url-result safe";
      resultEl.textContent = "URL appears safe";
    }
  }

  // ─── Open Options ───────────────────────────────────────────────────────

  document.getElementById("open-options").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (response) => {
      if (chrome.runtime.lastError) {
        resolve(null);
      } else {
        resolve(response);
      }
    });
  });
}

function setToggle(id, value) {
  const el = document.getElementById(id);
  if (el) el.checked = !!value;
}

async function updateSetting(key, value) {
  const update = {};
  update[key] = value;
  await sendMessage({ type: "update_settings", settings: update });
}

function setPageStatus(status, label) {
  const iconEl = document.getElementById("status-icon");
  const labelEl = document.getElementById("status-label");

  iconEl.className = "status-icon";

  if (status === "safe") {
    iconEl.classList.add("status-safe");
    iconEl.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  } else if (status === "warning") {
    iconEl.classList.add("status-warning");
    iconEl.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M12 9v4m0 4h.01M12 3l9.5 17H2.5L12 3z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  } else {
    iconEl.classList.add("status-danger");
    iconEl.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none">
      <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
    </svg>`;
  }

  labelEl.textContent = label;
}
