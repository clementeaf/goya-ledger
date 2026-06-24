// GOYA-ledger frontend — vanilla JS, calls Tauri commands via IPC.

const { invoke } = window.__TAURI__.core;

// ── Helpers ──

const $ = (sel) => document.querySelector(sel);
const show = (el, html) => { el.innerHTML = html; };

function jsonBlock(data) {
  return `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

function identityCard(id) {
  return `<div class="identity-item">
    <div class="did">${id.did}</div>
    <div class="meta">${id.algorithm} · ${id.created_at}</div>
  </div>`;
}

// ── Identity ──

async function createIdentity() {
  const btn = $("#btn-create-id");
  const passwordInput = $("#identity-password");
  const password = passwordInput.value;

  const valid = password.length >= 8;
  show(
    $("#identity-list"),
    valid ? "" : '<span class="tag error">Password debe tener al menos 8 caracteres</span>'
  );
  valid || (void 0);
  // ponytail: early return via guard — no nested if/else
  switch (valid) {
    case false: return;
    default: break;
  }

  btn.disabled = true;
  btn.textContent = "Creando...";

  try {
    await invoke("cmd_create_identity", { algorithm: "Ed25519", password });
    passwordInput.value = "";
    await refreshIdentities();
    show($("#notarize-result"), "");
  } catch (e) {
    show($("#identity-list"), `<span class="tag error">${e.message || e}</span>`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Crear Identidad";
  }
}

async function refreshIdentities() {
  try {
    const ids = await invoke("cmd_list_identities");
    const html = ids.length
      ? ids.map(identityCard).join("")
      : "<p style='color:var(--text-muted)'>Sin identidades. Crea una para empezar.</p>";
    show($("#identity-list"), html);
  } catch (e) {
    show($("#identity-list"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Notarize ──

async function notarizeFile(file) {
  show($("#notarize-result"), "<p>Procesando...</p>");

  try {
    const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
    const result = await invoke("cmd_notarize", {
      fileName: file.name,
      fileBytes: bytes,
    });
    show($("#notarize-result"), `
      <span class="tag success">Registrado</span>
      ${jsonBlock(result)}
    `);
  } catch (e) {
    show($("#notarize-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Verify ──

async function verifyHash() {
  const hash = $("#verify-hash").value.trim();
  show($("#verify-result"), "<p>Verificando...</p>");

  try {
    const result = await invoke("cmd_verify_notarization", { hash });
    show($("#verify-result"), `<span class="tag success">Encontrado</span>${jsonBlock(result)}`);
  } catch (e) {
    show($("#verify-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Node Status ──

async function refreshStatus() {
  try {
    const status = await invoke("cmd_node_status");
    const dot = $("#status-dot");
    const text = $("#status-text");

    dot.className = status.connected ? "dot online" : "dot offline";
    text.textContent = status.connected
      ? `Conectado · Bloque #${status.chain_height ?? "?"}`
      : "Desconectado";

    show($("#node-status"), jsonBlock(status));
  } catch (e) {
    show($("#node-status"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Event wiring ──

document.addEventListener("DOMContentLoaded", () => {
  // Identity
  $("#btn-create-id").addEventListener("click", createIdentity);

  // Notarize — drop zone
  const dropZone = $("#drop-zone");
  const fileInput = $("#file-input");

  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    file && notarizeFile(file);
  });
  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    file && notarizeFile(file);
  });

  // Verify
  $("#btn-verify").addEventListener("click", verifyHash);
  $("#verify-hash").addEventListener("keydown", (e) => {
    e.key === "Enter" && verifyHash();
  });

  // Initial load
  refreshIdentities();
  refreshStatus();

  // Refresh status every 30s
  setInterval(refreshStatus, 30000);
});
