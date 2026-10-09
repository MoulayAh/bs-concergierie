"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const ZONES = ["front_bumper", "rear_bumper", "hood", "roof", "left_side", "right_side",
    "windshield", "wheels", "interior", "other"];
  const SEVERITIES = ["minor", "moderate", "major"];
  const enc = new TextEncoder();
  let report = null;
  let cryptoOk = null;
  let meId = null; // id de l'utilisateur courant : inconnu tant qu'aucune route ne le fournit

  // ---------- helpers ----------
  function show(el, msg) { el.textContent = msg; el.hidden = !msg; }
  function clearMsgs() { show($("error"), ""); show($("info"), ""); }
  function info(m) { show($("info"), m); }
  function fail(e) {
    if (e && e.apiError) {
      const d = e.apiError.details;
      const reason = d && typeof d.reason === "string" ? " [" + d.reason + "]" : "";
      show($("error"), e.apiError.code + reason + " : " + e.apiError.message);
    }
    else show($("error"), (e && e.message) ? e.message : String(e));
  }
  function b64(buf) {
    let s = ""; const a = new Uint8Array(buf);
    for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s);
  }
  function hex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
  }
  // euros (texte) -> centimes entiers, sans float
  function eurosToCents(txt) {
    const m = /^\s*(\d{1,9})(?:[.,](\d{1,2}))?\s*$/.exec(txt);
    if (!m) throw new Error("Montant invalide (ex. 125,50)");
    return parseInt(m[1], 10) * 100 + parseInt((m[2] || "").padEnd(2, "0") || "0", 10);
  }
  function centsToEuros(c) {
    return String(Math.floor(c / 100)) + "," + String(c % 100).padStart(2, "0");
  }
  function base() {
    const id = $("contract").value.trim();
    if (!/^[0-9a-fA-F-]{8,40}$/.test(id)) throw new Error("Id de contrat invalide");
    return "/api/contracts/" + encodeURIComponent(id) + "/reports/" + $("kind").value;
  }
  function headers(extra) {
    const h = Object.assign({ "Authorization": "Bearer " + $("token").value.trim() }, extra || {});
    return h;
  }
  async function api(method, url, opts) {
    opts = opts || {};
    const h = headers(opts.headers);
    let body;
    if (opts.json !== undefined) { h["Content-Type"] = "application/json"; body = JSON.stringify(opts.json); }
    if (opts.form) body = opts.form;
    if (opts.idem) h["Idempotency-Key"] = crypto.randomUUID();
    let res;
    try { res = await fetch(url, { method, headers: h, body }); }
    catch (e) { throw new Error("Reseau indisponible : " + e.message); }
    if (opts.blob && res.ok) return res.blob();
    if (res.status === 204) return null;
    let data = null;
    const text = await res.text();
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = null; }
    if (!res.ok) {
      const err = new Error("HTTP " + res.status);
      err.apiError = (data && data.error) ? data.error
        : { code: "HTTP_" + res.status, message: "Reponse inattendue du serveur" };
      throw err;
    }
    return data;
  }
  async function guard(fn) { clearMsgs(); try { await fn(); } catch (e) { fail(e); } }

  // ---------- WebCrypto Ed25519 + IndexedDB ----------
  async function detectEd25519() {
    if (cryptoOk !== null) return cryptoOk;
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
      cryptoOk = true;
    } catch (_) { cryptoOk = false; }
    if (!cryptoOk) {
      show($("nocrypto"), "Ce navigateur ne gere pas Ed25519 dans WebCrypto (ou le contexte n'est pas " +
        "securise : utilisez http://localhost ou https). Signature impossible ; utilisez un navigateur recent.");
    }
    return cryptoOk;
  }
  function idb() {
    return new Promise((resolve, reject) => {
      const r = indexedDB.open("luxe-escrow", 1);
      r.onupgradeneeded = () => r.result.createObjectStore("keys");
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(new Error("IndexedDB indisponible"));
    });
  }
  async function idbOp(mode, fn) {
    const db = await idb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("keys", mode);
      const req = fn(tx.objectStore("keys"));
      tx.oncomplete = () => resolve(req && req.result);
      tx.onerror = () => reject(new Error("Erreur IndexedDB"));
    });
  }
  // un emplacement par jeton hache : evite de melanger les comptes
  async function slot() {
    const h = await crypto.subtle.digest("SHA-256", enc.encode($("token").value.trim()));
    return "key:" + hex(h).slice(0, 16);
  }
  async function getLocalKey() { return idbOp("readonly", (s) => s.get(awaitedSlot)); }
  let awaitedSlot = "";
  async function refreshLocalKey() {
    awaitedSlot = await slot();
    const k = await getLocalKey();
    $("localkey").textContent = k ? "presente (non exportable)" : "aucune pour ce jeton";
    return k;
  }

  async function genKey() {
    if (!(await detectEd25519())) throw new Error("Ed25519 indisponible dans ce navigateur");
    awaitedSlot = await slot();
    if (await getLocalKey()) throw new Error("Une cle locale existe deja pour ce jeton ; revoquez d'abord la cle serveur.");
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    if (raw.byteLength !== 32) throw new Error("Cle publique inattendue");
    await api("POST", "/api/me/keys", { json: { public_key: b64(raw) }, idem: true });
    // stockage local seulement apres acceptation serveur
    await idbOp("readwrite", (s) => s.put(pair.privateKey, awaitedSlot));
    await refreshLocalKey();
    info("Cle generee et enregistree.");
    await listKeys();
  }

  async function listKeys() {
    const data = await api("GET", "/api/me/keys");
    const list = (data && data.keys) || [];
    const ul = $("keys"); ul.textContent = "";
    for (const k of list) {
      const li = document.createElement("li");
      const state = k.revoked_at ? "revoquee" : "active";
      li.textContent = String(k.fingerprint || k.id) + " (" + state + ") ";
      if (!k.revoked_at) {
        const b = document.createElement("button");
        b.type = "button"; b.textContent = "Revoquer";
        b.addEventListener("click", () => guard(async () => {
          await api("DELETE", "/api/me/keys/" + encodeURIComponent(k.id));
          awaitedSlot = await slot();
          await idbOp("readwrite", (s) => s.delete(awaitedSlot));
          await refreshLocalKey();
          info("Cle revoquee (et supprimee localement).");
          await listKeys();
        }));
        li.appendChild(b);
      }
      ul.appendChild(li);
    }
  }

  async function signReport() {
    if ($("kind").value !== "checkout") throw new Error("Seul le rapport checkout se signe");
    if (!report || !report.report_hash) throw new Error("Rapport non fige : rien a signer");
    if (!(await detectEd25519())) throw new Error("Ed25519 indisponible dans ce navigateur");
    const key = await refreshLocalKey();
    if (!key) throw new Error("Aucune cle locale : generez et enregistrez une cle d'abord");
    // l'empreinte signee est recalculee localement et doit egaler celle du serveur
    const local = await localHash();
    if (local !== null && local !== report.report_hash) throw new Error("Empreinte locale differente : signature refusee");
    const contractId = $("contract").value.trim().toLowerCase();
    const msg = enc.encode("luxe-escrow:report:v1:" + contractId + ":" + $("kind").value + ":" + report.report_hash);
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, msg);
    await api("POST", base() + "/signatures", { json: { signature: b64(sig) }, idem: true });
    info("Signature enregistree.");
    await load();
  }

  // ---------- rapport ----------
  function canonicalText() {
    if (!report) return null;
    const c = report.canonical_json;
    return typeof c === "string" ? c : null;
  }
  async function localHash() {
    const t = canonicalText();
    if (t === null) return null;
    return hex(await crypto.subtle.digest("SHA-256", enc.encode(t)));
  }
  async function renderHash() {
    $("hash-server").textContent = (report && report.report_hash) || "-";
    const el = $("hash-match"); el.textContent = ""; el.className = "";
    $("hash-local").textContent = "-";
    $("canonical").textContent = "";
    if (!report) return;
    if (typeof report.canonical_json === "string") $("canonical").textContent = report.canonical_json;
    const local = await localHash();
    if (local === null) {
      if (report.report_hash) { el.textContent = "(JSON canonique non fourni en texte : recalcul impossible)"; }
      return;
    }
    $("hash-local").textContent = local;
    const ok = local === report.report_hash;
    el.textContent = ok ? "IDENTIQUES" : "DIFFERENTES";
    el.className = ok ? "ok" : "ko";
  }

  function damageRow(d) {
    d = d || {};
    const div = document.createElement("div"); div.className = "damage";
    const zone = document.createElement("select"); zone.className = "d-zone";
    for (const z of ZONES) { const o = document.createElement("option"); o.value = z; o.textContent = z; zone.appendChild(o); }
    zone.value = ZONES.includes(d.zone) ? d.zone : "other";
    const sev = document.createElement("select"); sev.className = "d-sev";
    for (const s of SEVERITIES) { const o = document.createElement("option"); o.value = s; o.textContent = s; sev.appendChild(o); }
    sev.value = SEVERITIES.includes(d.severity) ? d.severity : "minor";
    const desc = document.createElement("input"); desc.className = "d-desc"; desc.maxLength = 500;
    desc.placeholder = "Description"; desc.value = d.description || "";
    const fids = document.createElement("input"); fids.className = "d-files";
    fids.placeholder = "file_ids separes par des virgules"; fids.value = (d.file_ids || []).join(",");
    const rm = document.createElement("button"); rm.type = "button"; rm.textContent = "Retirer";
    rm.addEventListener("click", () => div.remove());
    div.append(zone, sev, desc, fids, rm);
    return div;
  }
  function render() {
    $("status").textContent = report ? (report.status + " - rev " + report.revision) : "aucun";
    const draft = report && report.status === "DRAFT";
    const editable = !report || draft;
    $("form").querySelectorAll("input,select,textarea").forEach((e) => { e.disabled = !editable; });
    $("save").disabled = !draft; $("finalize").disabled = !draft;
    $("create").disabled = !!report;
    $("supersede").disabled = !(report && report.status === "FROZEN");
    $("add-damage").disabled = !editable;
    if (report) {
      $("odometer").value = report.odometer_km ?? "";
      $("fuel").value = report.fuel_eighths ?? "";
      $("retention").value = centsToEuros(report.claimed_retention_cents || 0);
      $("notes").value = report.notes || "";
      const box = $("damages"); box.textContent = "";
      for (const d of report.damages || []) box.appendChild(damageRow(d));
    }
    // fichiers
    const ul = $("files"); ul.textContent = "";
    for (const f of report ? (report.files || []) : []) {
      const li = document.createElement("li");
      li.textContent = f.id + " - " + (f.original_name || "") + " " + f.mime + " " + f.size_bytes + " o ";
      const dl = document.createElement("button"); dl.type = "button"; dl.textContent = "Telecharger";
      dl.addEventListener("click", () => guard(async () => {
        const blob = await api("GET", base() + "/files/" + encodeURIComponent(f.id), { blob: true });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = f.original_name || f.id;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      }));
      li.appendChild(dl);
      if (draft && (meId === null || f.uploaded_by === meId)) {
        const del = document.createElement("button"); del.type = "button"; del.textContent = "Supprimer";
        del.addEventListener("click", () => guard(async () => {
          await api("DELETE", base() + "/files/" + encodeURIComponent(f.id));
          await load();
        }));
        li.appendChild(del);
      }
      ul.appendChild(li);
    }
    // signatures
    const sigs = report && report.signatures;
    $("sigs").textContent = Array.isArray(sigs) && sigs.length
      ? sigs.map((s) => s.party + " (" + String(s.signed_at || "") + ")").join(", ") : "aucune";
  }

  function collect() {
    const damages = Array.from($("damages").querySelectorAll(".damage")).map((div) => ({
      zone: div.querySelector(".d-zone").value,
      severity: div.querySelector(".d-sev").value,
      description: div.querySelector(".d-desc").value,
      file_ids: div.querySelector(".d-files").value.split(",").map((s) => s.trim()).filter(Boolean),
    }));
    const km = Number($("odometer").value), fuel = Number($("fuel").value);
    if (!Number.isInteger(km) || !Number.isInteger(fuel)) throw new Error("Kilometrage et carburant doivent etre entiers");
    return {
      odometer_km: km, fuel_eighths: fuel,
      claimed_retention_cents: eurosToCents($("retention").value),
      notes: $("notes").value, damages,
    };
  }

  async function renderHistory() {
    const ul = $("history"); ul.textContent = "";
    const data = await api("GET", base() + "/history");
    const list = (data && data.reports) || [];
    for (const r of list) {
      const li = document.createElement("li");
      li.textContent = "rev " + r.revision + " - " + r.status + " - " + (r.report_hash || "(brouillon)");
      ul.appendChild(li);
    }
  }

  async function load() {
    try {
      report = await api("GET", base());
    } catch (e) {
      if (e.apiError && e.apiError.code === "NOT_FOUND") { report = null; info("Aucun rapport : creez-le."); }
      else throw e;
    }
    render();
    await renderHash();
    await refreshLocalKey();
    if (report) await renderHistory(); else $("history").textContent = "";
  }

  // ---------- evenements ----------
  $("load").addEventListener("click", () => guard(load));
  $("kind").addEventListener("change", () => guard(load));
  $("add-damage").addEventListener("click", () => $("damages").appendChild(damageRow()));
  $("create").addEventListener("click", () => guard(async () => {
    const body = Object.assign({ kind: $("kind").value }, collect());
    report = await api("POST", "/api/contracts/" + encodeURIComponent($("contract").value.trim()) + "/reports",
      { json: body, idem: true });
    await load();
  }));
  $("form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    guard(async () => { report = await api("PUT", base(), { json: collect() }); await load(); info("Enregistre."); });
  });
  $("finalize").addEventListener("click", () => guard(async () => {
    report = await api("POST", base() + "/finalize", { idem: true });
    await load(); info("Rapport fige.");
  }));
  $("supersede").addEventListener("click", () => guard(async () => {
    report = await api("POST", base() + "/supersede", { idem: true });
    await load(); info("Nouvelle revision creee.");
  }));
  $("upload").addEventListener("click", () => guard(async () => {
    const f = $("file").files[0];
    if (!f) throw new Error("Choisissez un fichier");
    if (f.size > 10 * 1024 * 1024) throw new Error("Fichier trop volumineux (10 Mo maximum)");
    const fd = new FormData(); fd.append("file", f);
    await api("POST", base() + "/files", { form: fd });
    $("file").value = "";
    await load(); info("Fichier envoye.");
  }));
  $("genkey").addEventListener("click", () => guard(genKey));
  $("listkeys").addEventListener("click", () => guard(listKeys));
  $("sign").addEventListener("click", () => guard(signReport));

  detectEd25519().then(() => render());
})();
