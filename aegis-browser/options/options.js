/**
 * AEGIS Browser Guardian — Options Page Script
 */

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  await loadEventLog();

  // ─── Settings toggle handlers ───────────────────────────────────────────

  const settingsMap = {
    "opt-enabled": "enabled",
    "opt-malvertising": "block_malvertising",
    "opt-scareware": "block_scareware",
    "opt-downloads": "check_downloads",
    "opt-verify": "verify_software_urls",
    "opt-notifications": "notifications",
    "opt-native": "native_messaging",
  };

  for (const [id, key] of Object.entries(settingsMap)) {
    document.getElementById(id).addEventListener("change", async (e) => {
      const update = {};
      update[key] = e.target.checked;
      await sendMessage({ type: "update_settings", settings: update });
      showToast();
    });
  }

  // ─── Log actions ────────────────────────────────────────────────────────

  document.getElementById("btn-refresh-log").addEventListener("click", loadEventLog);

  document.getElementById("btn-clear-log").addEventListener("click", async () => {
    await chrome.storage.local.set({ eventLog: [] });
    await loadEventLog();
    showToast("Log cleared");
  });

  document.getElementById("btn-reset-stats").addEventListener("click", async () => {
    const freshStats = { blocked: 0, warned: 0, downloads_checked: 0, scareware_detected: 0 };
    await chrome.storage.local.set({ stats: freshStats });
    showToast("Stats reset");
  });
});

// ─── Load Settings ────────────────────────────────────────────────────────────

async function loadSettings() {
  const settings = await sendMessage({ type: "get_settings" });
  if (!settings) return;

  setChecked("opt-enabled", settings.enabled);
  setChecked("opt-malvertising", settings.block_malvertising);
  setChecked("opt-scareware", settings.block_scareware);
  setChecked("opt-downloads", settings.check_downloads);
  setChecked("opt-verify", settings.verify_software_urls);
  setChecked("opt-notifications", settings.notifications);
  setChecked("opt-native", settings.native_messaging);
}

// ─── Load Event Log ───────────────────────────────────────────────────────────

async function loadEventLog() {
  const data = await chrome.storage.local.get("eventLog");
  const log = data.eventLog || [];
  const container = document.getElementById("log-container");

  if (log.length === 0) {
    container.innerHTML = '<div class="log-empty">No events recorded yet</div>';
    return;
  }

  container.innerHTML = log
    .slice(0, 100) // Show last 100
    .map((entry) => {
      const time = formatTime(entry.timestamp);
      const typeClass = getTypeClass(entry.type);
      const detail = formatDetail(entry);
      return `
        <div class="log-entry">
          <span class="log-time">${escapeHtml(time)}</span>
          <span class="log-type ${typeClass}">${escapeHtml(entry.type)}</span>
          <span class="log-detail">${escapeHtml(detail)}</span>
        </div>
      `;
    })
    .join("");
}

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

function setChecked(id, value) {
  const el = document.getElementById(id);
  if (el) el.checked = !!value;
}

function showToast(text = "Settings saved") {
  const toast = document.getElementById("saved-toast");
  toast.textContent = text;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2000);
}

function formatTime(isoString) {
  try {
    const d = new Date(isoString);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return isoString || "—";
  }
}

function getTypeClass(type) {
  if (type.includes("block")) return "blocked";
  if (type.includes("warn")) return "warned";
  if (type.includes("scareware")) return "scareware";
  if (type.includes("phishing")) return "phishing";
  return "";
}

function formatDetail(entry) {
  const d = entry.data || {};
  if (d.url) {
    try {
      const u = new URL(d.url);
      return u.hostname + (d.reason ? ` — ${d.reason}` : "");
    } catch {
      return d.url.substring(0, 60);
    }
  }
  if (d.reason) return d.reason;
  if (d.pattern) return `Pattern: ${d.pattern}`;
  return JSON.stringify(d).substring(0, 80);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
