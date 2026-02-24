/**
 * AEGIS Browser Guardian — Content Script (Scareware Detector)
 *
 * Runs on every page to detect scareware/fake alert patterns:
 * - Fake virus warnings
 * - Fake tech support numbers
 * - Fullscreen lock attempts
 * - Audio alarm loops
 * - Fake scan animations
 */

(() => {
  "use strict";

  // Avoid running in extension pages
  if (window.location.protocol === "chrome-extension:") return;

  // ─── Detection Patterns ───────────────────────────────────────────────────

  const SCAREWARE_TEXT_PATTERNS = [
    /your (computer|pc|device|system) (is|has been) (infected|compromised|hacked|at risk)/i,
    /virus(es)? (detected|found|alert)/i,
    /trojan\s*(horse)?\s*(detected|found|warning)/i,
    /malware\s*(detected|found|warning|alert)/i,
    /spyware\s*(detected|found|warning)/i,
    /call\s*(now|immediately|this number|us)\s*[:.]?\s*[\d\-\(\)\+\s]{7,}/i,
    /toll[- ]free\s*[:.]?\s*[\d\-\(\)\+\s]{7,}/i,
    /microsoft\s*(support|technician|certified|warning|security)/i,
    /apple\s*(support|security|warning)\s*(alert|notice)/i,
    /windows\s*(defender|security|firewall)\s*(alert|warning|has detected)/i,
    /your\s*(personal|bank|financial)\s*(data|info|information)\s*(is|are)\s*(at risk|exposed|stolen)/i,
    /do not (close|shut|turn off|restart)/i,
    /your (browser|chrome|firefox|edge) (is|has been) (blocked|locked|compromised)/i,
    /unauthorized access/i,
    /pornographic\s*(material|content|virus)/i,
    /illegal activity\s*(detected|has been)/i,
    /contact\s*(microsoft|apple|google)\s*(certified|authorized)?\s*(tech|support)/i,
    /your ip (address )?(has been|is being) (tracked|logged|compromised)/i,
    /immediate action required/i,
    /security alert.*error code/i,
  ];

  const FAKE_SCAN_PATTERNS = [
    /scanning (your )?(computer|pc|system|device|files)/i,
    /threat[s]?\s*(found|detected|removed|cleaning)/i,
    /cleaning (in progress|your system)/i,
    /infection[s]?\s*:?\s*\d+/i,
    /risk level\s*:?\s*(critical|high|severe|extreme)/i,
  ];

  const PHONE_NUMBER_PATTERN = /(?:call|dial|phone|contact|ring|tel)\s*[:.]?\s*[\+]?1?\s*[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/gi;

  // ─── Detection Functions ──────────────────────────────────────────────────

  function getVisibleText() {
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const el = node.parentElement;
          if (!el) return NodeFilter.FILTER_REJECT;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        },
      }
    );

    let text = "";
    while (walker.nextNode()) {
      text += walker.currentNode.textContent + " ";
      if (text.length > 50000) break; // limit scan size
    }
    return text;
  }

  function checkTextPatterns(text) {
    const indicators = [];

    for (const pattern of SCAREWARE_TEXT_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        indicators.push({ type: "scareware_text", match: match[0].substring(0, 100) });
      }
    }

    for (const pattern of FAKE_SCAN_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        indicators.push({ type: "fake_scan", match: match[0].substring(0, 100) });
      }
    }

    const phones = text.match(PHONE_NUMBER_PATTERN);
    if (phones && phones.length > 0) {
      indicators.push({ type: "phone_number", match: phones[0].substring(0, 50) });
    }

    return indicators;
  }

  function checkFullscreenLock() {
    const indicators = [];

    // Check for fullscreen API abuse
    if (document.fullscreenElement) {
      indicators.push({ type: "fullscreen_lock", match: "Page entered fullscreen" });
    }

    // Check for elements covering the entire viewport
    const overlays = document.querySelectorAll("div, section, aside");
    for (const el of overlays) {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      if (
        rect.width >= window.innerWidth * 0.95 &&
        rect.height >= window.innerHeight * 0.95 &&
        (style.position === "fixed" || style.position === "absolute") &&
        parseInt(style.zIndex || "0") > 9000
      ) {
        indicators.push({ type: "fullscreen_overlay", match: `z-index: ${style.zIndex}` });
        break;
      }
    }

    return indicators;
  }

  function checkAudioAbuse() {
    const indicators = [];
    const audios = document.querySelectorAll("audio, video");

    for (const el of audios) {
      if (!el.paused && el.loop) {
        indicators.push({ type: "audio_loop", match: `Looping ${el.tagName.toLowerCase()} element` });
      }
    }

    return indicators;
  }

  function checkDialogAbuse() {
    const indicators = [];

    // Detect pages that override beforeunload to prevent leaving
    const scripts = document.querySelectorAll("script");
    for (const script of scripts) {
      const content = script.textContent || "";
      if (content.includes("onbeforeunload") || content.includes("beforeunload")) {
        if (content.includes("alert") || content.includes("confirm") || content.includes("prompt")) {
          indicators.push({ type: "exit_prevention", match: "beforeunload with dialog" });
          break;
        }
      }
    }

    return indicators;
  }

  function checkFakeUI() {
    const indicators = [];

    // Look for fake Windows/Mac UI elements
    const imgs = document.querySelectorAll("img");
    for (const img of imgs) {
      const src = (img.src || "").toLowerCase();
      const alt = (img.alt || "").toLowerCase();
      if (
        src.includes("windows-defender") ||
        src.includes("microsoft-logo") ||
        src.includes("apple-security") ||
        alt.includes("windows defender") ||
        alt.includes("microsoft security")
      ) {
        indicators.push({ type: "fake_ui", match: `Fake brand image: ${src.substring(0, 80)}` });
      }
    }

    // Check for fake progress bars / scan animations
    const allElements = document.querySelectorAll("[class*=scan], [class*=progress], [id*=scan], [id*=progress]");
    let scanElements = 0;
    for (const el of allElements) {
      const text = (el.textContent || "").toLowerCase();
      if (text.includes("scanning") || text.includes("detecting") || text.includes("removing")) {
        scanElements++;
      }
    }
    if (scanElements >= 2) {
      indicators.push({ type: "fake_scan_ui", match: `${scanElements} fake scan UI elements` });
    }

    return indicators;
  }

  // ─── Main Detection ───────────────────────────────────────────────────────

  function runDetection() {
    if (!document.body) return;

    const indicators = [];

    const text = getVisibleText();
    indicators.push(...checkTextPatterns(text));
    indicators.push(...checkFullscreenLock());
    indicators.push(...checkAudioAbuse());
    indicators.push(...checkDialogAbuse());
    indicators.push(...checkFakeUI());

    // Threshold: 3+ indicators = likely scareware
    if (indicators.length >= 3) {
      reportScareware(indicators);
    }
  }

  function reportScareware(indicators) {
    // Notify background script
    chrome.runtime.sendMessage(
      { type: "scareware_detected", indicators },
      (response) => {
        if (chrome.runtime.lastError) {
          console.warn("[AEGIS] Failed to contact background:", chrome.runtime.lastError.message);
          return;
        }
        if (response && response.action === "overlay") {
          showWarningOverlay(indicators);
        }
      }
    );
  }

  // ─── Warning Overlay ──────────────────────────────────────────────────────

  function showWarningOverlay(indicators) {
    // Remove any existing overlay
    const existing = document.getElementById("aegis-warning-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "aegis-warning-overlay";
    overlay.innerHTML = `
      <div class="aegis-overlay-backdrop">
        <div class="aegis-overlay-card">
          <div class="aegis-overlay-header">
            <div class="aegis-shield-icon">
              <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                <path d="M24 4L6 12v12c0 11.1 7.7 21.5 18 24 10.3-2.5 18-12.9 18-24V12L24 4z" fill="#2563EB"/>
                <path d="M20 26l-4-4-2 2 6 6 12-12-2-2-10 10z" fill="white"/>
              </svg>
            </div>
            <h1>AEGIS Browser Guardian</h1>
          </div>
          <div class="aegis-overlay-body">
            <h2>This page appears to be a scam</h2>
            <p>AEGIS has detected <strong>${indicators.length} indicators</strong> of scareware or fake alert content on this page.</p>
            <div class="aegis-indicators">
              <h3>Detected indicators:</h3>
              <ul>
                ${indicators
                  .slice(0, 5)
                  .map((i) => `<li><span class="aegis-tag">${escapeHtml(i.type)}</span> ${escapeHtml(i.match)}</li>`)
                  .join("")}
                ${indicators.length > 5 ? `<li>...and ${indicators.length - 5} more</li>` : ""}
              </ul>
            </div>
            <p class="aegis-warning-text">
              <strong>Do NOT</strong> call any phone numbers shown on this page.<br>
              <strong>Do NOT</strong> download any software from this page.<br>
              This is likely a scam designed to trick you.
            </p>
          </div>
          <div class="aegis-overlay-actions">
            <button class="aegis-btn aegis-btn-primary" id="aegis-leave-page">Leave this page</button>
            <button class="aegis-btn aegis-btn-secondary" id="aegis-dismiss">I understand the risks, continue</button>
          </div>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    // Stop any audio/video
    document.querySelectorAll("audio, video").forEach((el) => {
      el.pause();
      el.muted = true;
    });

    // Exit fullscreen if active
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    // Button handlers
    document.getElementById("aegis-leave-page").addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "about:blank";
      }
    });

    document.getElementById("aegis-dismiss").addEventListener("click", () => {
      overlay.remove();
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // ─── Run Detection ────────────────────────────────────────────────────────

  // Run after DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      setTimeout(runDetection, 1000); // Wait for dynamic content
    });
  } else {
    setTimeout(runDetection, 1000);
  }

  // Also observe for late-loaded scareware content
  const observer = new MutationObserver(() => {
    clearTimeout(observer._debounce);
    observer._debounce = setTimeout(runDetection, 2000);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Stop observing after 30 seconds to avoid performance impact
  setTimeout(() => observer.disconnect(), 30000);
})();
