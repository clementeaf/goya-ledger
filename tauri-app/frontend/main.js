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
    syncSelectors(ids);
  } catch (e) {
    show($("#identity-list"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Notarize ──

async function notarizeFile(file) {
  const did = $("#notarize-did").value;
  const password = $("#notarize-password").value;

  if (!did) {
    show($("#notarize-result"), '<span class="tag error">Selecciona una identidad</span>');
    return;
  }
  if (!password) {
    show($("#notarize-result"), '<span class="tag error">Ingresa el password de la identidad</span>');
    return;
  }

  show($("#notarize-result"), "<p>Firmando y registrando...</p>");

  try {
    const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
    const result = await invoke("cmd_notarize", {
      did,
      password,
      fileName: file.name,
      fileBytes: bytes,
    });
    $("#notarize-password").value = "";
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

// ── Wallet ──

async function refreshBalance() {
  const did = $("#wallet-did").value;
  show($("#wallet-balance"), did ? "<p>Consultando...</p>" : "");
  switch (true) {
    case !did: return;
    default: break;
  }

  try {
    const bal = await invoke("cmd_get_balance", { address: did });
    show($("#wallet-balance"), `
      <div class="balance-display">
        <span class="balance-amount">${bal.balance}</span> GOYA
        <span class="balance-nonce">nonce: ${bal.nonce}</span>
      </div>
    `);
  } catch (e) {
    show($("#wallet-balance"), `<span class="tag error">${e.message || e}</span>`);
  }
}

async function requestFaucet() {
  const did = $("#wallet-did").value;
  switch (true) {
    case !did:
      show($("#wallet-balance"), '<span class="tag error">Selecciona identidad</span>');
      return;
    default: break;
  }

  const btn = $("#btn-faucet");
  btn.disabled = true;
  btn.textContent = "Enviando...";

  try {
    const result = await invoke("cmd_request_faucet", { recipient: did, amount: 1000 });
    show($("#wallet-balance"), `<span class="tag success">+${result.amount} GOYA</span>`);
    await refreshBalance();
  } catch (e) {
    show($("#wallet-balance"), `<span class="tag error">${e.message || e}</span>`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Faucet (1000)";
  }
}

// ── Transfer ──

async function sendTransfer() {
  const fromDid = $("#transfer-from").value;
  const toAddress = $("#transfer-to").value.trim();
  const amount = parseInt($("#transfer-amount").value, 10);
  const password = $("#transfer-password").value;

  const errors = [
    [!fromDid, "Selecciona identidad origen"],
    [!toAddress, "Ingresa DID destino"],
    [!amount || amount <= 0, "Ingresa cantidad valida"],
    [!password, "Ingresa password"],
  ].filter(([cond]) => cond).map(([, msg]) => msg);

  switch (errors.length) {
    case 0: break;
    default:
      show($("#transfer-result"), `<span class="tag error">${errors[0]}</span>`);
      return;
  }

  const btn = $("#btn-transfer");
  btn.disabled = true;
  btn.textContent = "Enviando...";

  try {
    const result = await invoke("cmd_send_transfer", {
      fromDid, password, toAddress, amount,
    });
    $("#transfer-password").value = "";
    show($("#transfer-result"), `
      <span class="tag success">Transferido</span>
      ${jsonBlock(result)}
    `);
  } catch (e) {
    show($("#transfer-result"), `<span class="tag error">${e.message || e}</span>`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Enviar";
  }
}

// ── Transaction History ──

async function loadHistory() {
  const did = $("#history-did").value;
  switch (true) {
    case !did:
      show($("#tx-history"), '<span class="tag error">Selecciona identidad</span>');
      return;
    default: break;
  }

  show($("#tx-history"), "<p>Cargando...</p>");

  try {
    const txs = await invoke("cmd_get_transactions", { address: did });
    const html = txs.length
      ? txs.map(tx => `<div class="identity-item">
          <div class="did">${tx.input_did === did ? "→" : "←"} ${tx.input_did === did ? tx.output_recipient : tx.input_did}</div>
          <div class="meta">${tx.amount} GOYA · bloque #${tx.block_height}</div>
        </div>`).join("")
      : "<p style='color:var(--text-muted)'>Sin transacciones.</p>";
    show($("#tx-history"), html);
  } catch (e) {
    show($("#tx-history"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Document Transfer ──

async function transferDoc() {
  const did = $("#doc-transfer-did").value;
  const contentHash = $("#doc-transfer-hash").value.trim();
  const toDid = $("#doc-transfer-to").value.trim();
  const password = $("#doc-transfer-password").value;

  const errors = [
    [!did, "Selecciona identidad"],
    [!contentHash, "Ingresa hash del documento"],
    [!toDid, "Ingresa DID destino"],
    [!password, "Ingresa password"],
  ].filter(([cond]) => cond).map(([, msg]) => msg);

  switch (errors.length) {
    case 0: break;
    default:
      show($("#doc-transfer-result"), `<span class="tag error">${errors[0]}</span>`);
      return;
  }

  const btn = $("#btn-doc-transfer");
  btn.disabled = true;
  btn.textContent = "Transfiriendo...";

  try {
    const result = await invoke("cmd_transfer_document", {
      did, password, contentHash, toDid,
    });
    $("#doc-transfer-password").value = "";
    show($("#doc-transfer-result"), `
      <span class="tag success">Transferido</span>
      ${jsonBlock(result)}
    `);
  } catch (e) {
    show($("#doc-transfer-result"), `<span class="tag error">${e.message || e}</span>`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Transferir";
  }
}

async function queryOwner() {
  const hash = $("#provenance-hash").value.trim();
  switch (true) {
    case !hash:
      show($("#provenance-result"), '<span class="tag error">Ingresa hash</span>');
      return;
    default: break;
  }

  try {
    const owner = await invoke("cmd_get_document_owner", { contentHash: hash });
    show($("#provenance-result"), `
      <div class="identity-item">
        <div class="did">Propietario: ${owner.owner}</div>
        <div class="meta">Firmante original: ${owner.original_signer} · ${owner.transfer_count} transferencia(s)</div>
      </div>
    `);
  } catch (e) {
    show($("#provenance-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

async function queryProvenance() {
  const hash = $("#provenance-hash").value.trim();
  switch (true) {
    case !hash:
      show($("#provenance-result"), '<span class="tag error">Ingresa hash</span>');
      return;
    default: break;
  }

  try {
    const prov = await invoke("cmd_get_provenance", { contentHash: hash });
    show($("#provenance-result"), jsonBlock(prov));
  } catch (e) {
    show($("#provenance-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Governance ──

async function loadProposals() {
  show($("#proposals-list"), "<p>Cargando...</p>");
  try {
    const proposals = await invoke("cmd_list_proposals");
    const html = proposals.length
      ? proposals.map(p => `<div class="identity-item">
          <div class="did">#${p.id} — ${p.description}</div>
          <div class="meta">${p.status} · deposito: ${p.deposit} · por: ${p.proposer}</div>
        </div>`).join("")
      : "<p style='color:var(--text-muted)'>Sin propuestas.</p>";
    show($("#proposals-list"), html);
  } catch (e) {
    show($("#proposals-list"), `<span class="tag error">${e.message || e}</span>`);
  }
}

async function createProposal() {
  const proposer = $("#proposal-proposer").value;
  const title = $("#proposal-title").value.trim();
  const desc = $("#proposal-desc").value.trim();
  const deposit = parseInt($("#proposal-deposit").value, 10) || 0;

  const errors = [
    [!proposer, "Selecciona proponente"],
    [!title, "Ingresa titulo"],
    [!desc, "Ingresa descripcion"],
  ].filter(([cond]) => cond).map(([, msg]) => msg);

  switch (errors.length) {
    case 0: break;
    default:
      show($("#create-proposal-result"), `<span class="tag error">${errors[0]}</span>`);
      return;
  }

  try {
    const result = await invoke("cmd_create_proposal", { proposer, title, description: desc, deposit });
    show($("#create-proposal-result"), `<span class="tag success">Propuesta creada</span>${jsonBlock(result)}`);
    $("#proposal-title").value = "";
    $("#proposal-desc").value = "";
    await loadProposals();
  } catch (e) {
    show($("#create-proposal-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

async function castVote() {
  const did = $("#vote-did").value;
  const proposalId = parseInt($("#vote-proposal-id").value, 10);
  const option = $("#vote-option").value;
  const password = $("#vote-password").value;

  const errors = [
    [!did, "Selecciona identidad"],
    [!proposalId, "Ingresa ID de propuesta"],
    [!password, "Ingresa password"],
  ].filter(([cond]) => cond).map(([, msg]) => msg);

  switch (errors.length) {
    case 0: break;
    default:
      show($("#vote-result"), `<span class="tag error">${errors[0]}</span>`);
      return;
  }

  try {
    const tally = await invoke("cmd_cast_vote", { did, password, proposalId, option });
    $("#vote-password").value = "";
    show($("#vote-result"), `
      <span class="tag success">Voto registrado</span>
      ${jsonBlock(tally)}
    `);
  } catch (e) {
    show($("#vote-result"), `<span class="tag error">${e.message || e}</span>`);
  }
}

// ── Sync all identity selectors ──

function syncSelectors(ids) {
  ["#notarize-did", "#wallet-did", "#transfer-from", "#history-did", "#proposal-proposer", "#vote-did", "#doc-transfer-did"].forEach(sel => {
    const el = $(sel);
    const prev = el.value;
    el.innerHTML = '<option value="">Selecciona identidad...</option>'
      + ids.map(id => `<option value="${id.did}">${id.did}</option>`).join("");
    el.value = ids.some(id => id.did === prev) ? prev : "";
  });
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

  // Wallet
  $("#btn-refresh-balance").addEventListener("click", refreshBalance);
  $("#btn-faucet").addEventListener("click", requestFaucet);

  // Transfer
  $("#btn-transfer").addEventListener("click", sendTransfer);

  // History
  $("#btn-history").addEventListener("click", loadHistory);

  // Document transfer
  $("#btn-doc-transfer").addEventListener("click", transferDoc);
  $("#btn-owner").addEventListener("click", queryOwner);
  $("#btn-provenance").addEventListener("click", queryProvenance);

  // Governance
  $("#btn-load-proposals").addEventListener("click", loadProposals);
  $("#btn-create-proposal").addEventListener("click", createProposal);
  $("#btn-vote").addEventListener("click", castVote);

  // Initial load
  refreshIdentities();
  refreshStatus();

  // Refresh status every 30s
  setInterval(refreshStatus, 30000);
});
