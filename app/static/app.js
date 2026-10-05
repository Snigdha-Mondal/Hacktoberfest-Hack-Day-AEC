/**
 * SafeDrop — Frontend Application Logic
 * Handles drag-and-drop, bounding box rendering, live preview updates,
 * and sanitized export downloads.
 */

// Application State
let currentSession = null;
let actionOverrides = {}; // { finding_id: "blackout" | "blur" | "pixelate" | "none" }

// DOM Elements
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const btnBrowse = document.getElementById("btn-browse");
const heroView = document.getElementById("hero-view");
const scanLoading = document.getElementById("scan-loading");
const workbench = document.getElementById("workbench");
const btnBackHero = document.getElementById("btn-back-hero");
const btnWatchDemo = document.getElementById("btn-watch-demo");
const btnPlaySample = document.getElementById("btn-play-sample");
const menuToggle = document.getElementById("menu-toggle");
const mainHeader = document.getElementById("main-header");

// Workbench Elements
const wbFilename = document.getElementById("wb-filename");
const wbHash = document.getElementById("wb-hash");
const wbRiskBadge = document.getElementById("wb-risk-badge");
const countCritical = document.getElementById("count-critical");
const countSensitive = document.getElementById("count-sensitive");
const countMetadata = document.getElementById("count-metadata");
const textVerdict = document.getElementById("text-verdict");
const imgOriginal = document.getElementById("img-original");
const imgPreview = document.getElementById("img-preview");
const bboxOverlay = document.getElementById("bbox-overlay");
const findingsList = document.getElementById("findings-list");
const btnExportSafe = document.getElementById("btn-export-safe");
const exportBtnText = document.getElementById("export-btn-text");
const btnAuditReport = document.getElementById("btn-audit-report");
const btnUploadNew = document.getElementById("btn-upload-new");
const btnRedactAll = document.getElementById("btn-redact-all");
const btnResetAll = document.getElementById("btn-reset-all");

// Quick Sample Buttons
const sampleDev = document.getElementById("sample-dev");
const sampleBadge = document.getElementById("sample-badge");
const sampleContract = document.getElementById("sample-contract");

// Setup Event Listeners
function init() {
  if (btnBrowse) {
    btnBrowse.addEventListener("click", () => fileInput && fileInput.click());
  }

  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files.length > 0) uploadAndScan(e.target.files[0]);
    });
  }

  // Responsive mobile menu toggle
  if (menuToggle && mainHeader) {
    menuToggle.addEventListener("click", () => {
      const isOpen = mainHeader.classList.toggle("menu-open");
      menuToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });
  }

  // Dropzone card drag and drop handlers
  if (dropzone) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        uploadAndScan(e.dataTransfer.files[0]);
      }
    });
    // Clicking the demo card visual opens file picker if play button wasn't clicked
    dropzone.addEventListener("click", (e) => {
      if (e.target.closest("#btn-play-sample")) return;
      if (fileInput) fileInput.click();
    });
  }

  // Window-level drag and drop support
  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (btnBrowse) btnBrowse.classList.add("dragover");
  });
  window.addEventListener("dragleave", (e) => {
    if (!e.relatedTarget && btnBrowse) {
      btnBrowse.classList.remove("dragover");
    }
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    if (btnBrowse) btnBrowse.classList.remove("dragover");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      uploadAndScan(e.dataTransfer.files[0]);
    }
  });

  const navPreflight = document.getElementById("nav-preflight");
  if (navPreflight) {
    navPreflight.addEventListener("click", (e) => {
      e.preventDefault();
      resetToUpload();
    });
  }

  if (btnBackHero) btnBackHero.addEventListener("click", resetToUpload);
  if (btnUploadNew) btnUploadNew.addEventListener("click", resetToUpload);
  if (btnExportSafe) btnExportSafe.addEventListener("click", exportSanitized);
  if (btnAuditReport) btnAuditReport.addEventListener("click", downloadAuditReport);

  if (btnWatchDemo) {
    btnWatchDemo.addEventListener("click", () => loadSampleImage("developer_screenshot.png"));
  }
  if (btnPlaySample) {
    btnPlaySample.addEventListener("click", (e) => {
      e.stopPropagation();
      loadSampleImage("developer_screenshot.png");
    });
  }

  if (btnRedactAll) {
    btnRedactAll.addEventListener("click", () => {
      if (!currentSession) return;
      currentSession.report.findings.forEach((f) => {
        actionOverrides[f.id] = "blackout";
      });
      renderFindingsDeck();
      updateLivePreview();
    });
  }

  if (btnResetAll) {
    btnResetAll.addEventListener("click", () => {
      actionOverrides = {};
      renderFindingsDeck();
      updateLivePreview();
    });
  }

  // Quick Samples
  if (sampleDev) sampleDev.addEventListener("click", () => loadSampleImage("developer_screenshot.png"));
  if (sampleBadge) sampleBadge.addEventListener("click", () => loadSampleImage("employee_badge.jpg"));
  if (sampleContract) sampleContract.addEventListener("click", () => loadSampleImage("legal_contract.png"));

  window.addEventListener("resize", () => {
    if (currentSession) drawBoundingBoxes();
  });
}

async function loadSampleImage(filename) {
  try {
    showLoading(true, `Loading sample fixture '${filename}'...`);
    const res = await fetch(`/static/samples/${filename}`);
    if (!res.ok) {
      // Fallback: generate sample via synthetic canvas if not in /static/samples
      createMockCanvasAndScan(filename);
      return;
    }
    const blob = await res.blob();
    const file = new File([blob], filename, { type: blob.type || "image/png" });
    uploadAndScan(file);
  } catch (err) {
    createMockCanvasAndScan(filename);
  }
}

function createMockCanvasAndScan(filename) {
  const canvas = document.createElement("canvas");
  canvas.width = 700;
  canvas.height = 350;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#161b22";
  ctx.fillRect(0, 0, 700, 350);

  ctx.fillStyle = "#10b981";
  ctx.font = "bold 16px monospace";
  ctx.fillText("# SafeDrop Developer Screenshot (.env)", 30, 40);

  ctx.fillStyle = "#e2e8f0";
  ctx.fillText("OPENAI_API_KEY=sk-proj-99887766554433221100aabbccddeeff", 30, 90);
  ctx.fillText("SUPPORT_EMAIL=snigdha@safedrop.dev", 30, 130);
  ctx.fillText("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", 30, 170);
  ctx.fillText("BILLING_CARD=4532 0150 1234 5671", 30, 210);

  canvas.toBlob((blob) => {
    const file = new File([blob], filename, { type: "image/png" });
    uploadAndScan(file);
  }, "image/png");
}

function showLoading(show, message) {
  if (show) {
    if (heroView) heroView.style.display = "none";
    workbench.style.display = "none";
    scanLoading.style.display = "flex";
    if (message) document.getElementById("loading-step").textContent = message;
  } else {
    scanLoading.style.display = "none";
  }
}

async function uploadAndScan(file) {
  showLoading(true, "Scanning file with deterministic detectors & Gemma 4...");
  actionOverrides = {};

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      let errorMsg = `Server error (${res.status})`;
      try {
        const err = await res.json();
        if (err && err.detail) errorMsg = err.detail;
      } catch (_) {
        const text = await res.text();
        if (text) errorMsg = text.substring(0, 150);
      }
      throw new Error(errorMsg);
    }

    currentSession = await res.json();
    displayWorkbench();
  } catch (err) {
    alert("Error scanning file: " + err.message);
    resetToUpload();
  } finally {
    showLoading(false);
  }
}

function displayWorkbench() {
  if (heroView) heroView.style.display = "none";
  workbench.style.display = "flex";

  const { file_name, file_hash, report, image_data } = currentSession;

  // Header info
  wbFilename.textContent = file_name;
  wbHash.textContent = `SHA-256: ${file_hash.substring(0, 16)}...`;
  exportBtnText.textContent = `Download Safe Copy (${file_name.replace(/\.[^/.]+$/, "")}-safedrop.png)`;

  // Risk Pill
  wbRiskBadge.textContent = `${report.overall_risk.toUpperCase()} RISK`;
  wbRiskBadge.className = `bar-risk-pill ${report.overall_risk.toLowerCase()}`;

  // Counts
  const critCount = report.findings.filter((f) => f.risk === "critical").length;
  const sensCount = report.findings.filter((f) => f.risk !== "critical").length;

  countCritical.textContent = critCount;
  countSensitive.textContent = sensCount;

  if (report.safe_to_share_without_changes) {
    textVerdict.textContent = "SAFE TO SHARE";
    textVerdict.style.color = "var(--accent-safe)";
  } else {
    textVerdict.textContent = "BLOCKED";
    textVerdict.style.color = "var(--accent-critical)";
  }

  // Load Original Image
  imgOriginal.onload = () => {
    requestAnimationFrame(() => {
      drawBoundingBoxes();
      updateLivePreview();
    });
  };
  imgOriginal.src = image_data;

  // Responsive resize observer to re-align overlay if image scales
  if (window.ResizeObserver && !window.__imgResizeObserver) {
    window.__imgResizeObserver = new ResizeObserver(() => {
      if (currentSession && imgOriginal.complete) {
        requestAnimationFrame(drawBoundingBoxes);
      }
    });
    window.__imgResizeObserver.observe(imgOriginal);
  }

  renderFindingsDeck();
}

function drawBoundingBoxes() {
  bboxOverlay.innerHTML = "";
  if (!currentSession || !imgOriginal.complete) return;

  const natW = imgOriginal.naturalWidth;
  const natH = imgOriginal.naturalHeight;
  const dispW = imgOriginal.clientWidth;
  const dispH = imgOriginal.clientHeight;

  if (natW === 0 || dispW === 0) return;

  // Pin overlay exactly to displayed image bounds
  bboxOverlay.style.width = `${dispW}px`;
  bboxOverlay.style.height = `${dispH}px`;
  bboxOverlay.style.left = `${imgOriginal.offsetLeft}px`;
  bboxOverlay.style.top = `${imgOriginal.offsetTop}px`;
  bboxOverlay.setAttribute("viewBox", `0 0 ${natW} ${natH}`);
  bboxOverlay.setAttribute("preserveAspectRatio", "none");

  currentSession.report.findings.forEach((f) => {
    if (!f.location) return;

    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", f.location.x);
    rect.setAttribute("y", f.location.y);
    rect.setAttribute("width", f.location.width);
    rect.setAttribute("height", f.location.height);
    rect.setAttribute("id", `bbox-${f.id}`);
    rect.setAttribute(
      "class",
      f.risk === "critical" ? "bbox-rect" : "bbox-rect medium"
    );

    rect.addEventListener("mouseenter", () => highlightFinding(f.id, true));
    rect.addEventListener("mouseleave", () => highlightFinding(f.id, false));
    rect.addEventListener("click", () => {
      const card = document.getElementById(`finding-card-${f.id}`);
      if (card) card.scrollIntoView({ behavior: "smooth", block: "center" });
      highlightFinding(f.id, true);
    });

    bboxOverlay.appendChild(rect);
  });
}

function renderFindingsDeck() {
  findingsList.innerHTML = "";

  if (!currentSession.report.findings || currentSession.report.findings.length === 0) {
    findingsList.innerHTML = `
      <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
        No privacy risks or sensitive tokens detected in this image. Safe to share!
      </div>
    `;
    return;
  }

  currentSession.report.findings.forEach((f) => {
    const currentAction = actionOverrides[f.id] || f.recommended_action;

    const card = document.createElement("div");
    card.className = "finding-card";
    card.id = `finding-card-${f.id}`;

    card.innerHTML = `
      <div class="finding-card-info">
        <div class="finding-card-header">
          <span class="category-badge ${f.risk.toLowerCase()}">${f.category}</span>
          <span class="finding-label">${f.label}</span>
        </div>
        <div>
          <span class="finding-evidence">${escapeHtml(f.masked_evidence)}</span>
        </div>
        <div class="finding-reason">${escapeHtml(f.reason)}</div>
      </div>
      <div class="finding-controls">
        <select class="action-select" id="action-select-${f.id}">
          <option value="blackout" ${currentAction === "blackout" ? "selected" : ""}>Solid Blackout</option>
          <option value="blur" ${currentAction === "blur" ? "selected" : ""}>Gaussian Blur</option>
          <option value="pixelate" ${currentAction === "pixelate" ? "selected" : ""}>Pixelate</option>
          <option value="none" ${currentAction === "none" ? "selected" : ""}>Keep (No Redaction)</option>
        </select>
      </div>
    `;

    // Listeners
    const select = card.querySelector(`#action-select-${f.id}`);
    select.addEventListener("change", (e) => {
      actionOverrides[f.id] = e.target.value;
      updateLivePreview();
    });

    card.addEventListener("mouseenter", () => highlightFinding(f.id, true));
    card.addEventListener("mouseleave", () => highlightFinding(f.id, false));

    findingsList.appendChild(card);
  });
}

function highlightFinding(id, active) {
  const rect = document.getElementById(`bbox-${id}`);
  const card = document.getElementById(`finding-card-${id}`);

  if (rect) rect.classList.toggle("active", active);
  if (card) card.classList.toggle("active", active);
}

async function updateLivePreview() {
  if (!currentSession) return;

  try {
    const res = await fetch("/api/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_id: currentSession.file_id,
        action_overrides: actionOverrides,
      }),
    });

    if (res.ok) {
      const data = await res.json();
      imgPreview.src = data.preview_data;
    }
  } catch (err) {
    console.error("Preview update error:", err);
  }
}

async function exportSanitized() {
  if (!currentSession) return;

  try {
    const res = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_id: currentSession.file_id,
        action_overrides: actionOverrides,
      }),
    });

    if (!res.ok) throw new Error("Export failed.");

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const originalStem = currentSession.file_name.replace(/\.[^/.]+$/, "");
    a.download = `${originalStem}-safedrop.png`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert("Error downloading sanitized copy: " + err.message);
  }
}

async function downloadAuditReport() {
  if (!currentSession) return;

  try {
    const res = await fetch(`/api/audit/${currentSession.file_id}`);
    if (!res.ok) throw new Error("Could not retrieve audit certificate.");

    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `safedrop_audit_${currentSession.file_id.substring(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert("Error downloading audit report: " + err.message);
  }
}

function resetToUpload() {
  currentSession = null;
  actionOverrides = {};
  if (fileInput) fileInput.value = "";
  if (workbench) workbench.style.display = "none";
  if (heroView) heroView.style.display = "";
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Start application
init();
