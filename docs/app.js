/* CryptoShield Web (client-side)
   IMPORTANT REALITY CHECK:
   - Any JavaScript/HTML/CSS shipped to a browser can be viewed or copied by a determined user.
   - The measures below are deterrents + UI hardening, NOT a true way to hide source code.
*/

"use strict";

// === Python backend compatibility ===
// Python uses: MAGIC=b"CSP1", SALT_LEN=16, KDF_ITERS=200_000
// payload = base64url( MAGIC + salt + fernet_token_bytes )
// where fernet_token_bytes is ASCII of Fernet token (already base64url)
const MAGIC = new TextEncoder().encode("CSP1");
const SALT_LEN = 16;
const KDF_ITERS = 200000; // ✅ MUST match Python backend (200_000)

// === Domain lock (edit these) ===
// For GitHub Pages repo: https://code-help-on-python.github.io/Crypto-tool/
// location.hostname = "code-help-on-python.github.io"
// location.pathname starts with "/Crypto-tool/"
const ALLOWED_HOSTS = ["code-help-on-python.github.io", "localhost", "127.0.0.1"];
const ALLOWED_PATH_PREFIX = "/Crypto-tool"; // no trailing slash

// --- Elements ---
const passphraseDecrypt = document.getElementById("passphrase-decrypt");
const tokenInput = document.getElementById("token");
const outputBox = document.getElementById("output");
const statusEl = document.getElementById("status");
const decryptBtn = document.getElementById("decrypt");
const copyBtn = document.getElementById("copy");
const clearBtn = document.getElementById("clear");

const passphraseEncrypt = document.getElementById("passphrase-encrypt");
const plaintextInput = document.getElementById("plaintext");
const tokenOut = document.getElementById("token-out");
const statusEncEl = document.getElementById("status-encrypt");
const encryptBtn = document.getElementById("encrypt");
const copyEncBtn = document.getElementById("copy-encrypt");
const clearEncBtn = document.getElementById("clear-encrypt");

const tabButtons = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");
const themeButtons = document.querySelectorAll(".theme-btn");
const togglePassButtons = document.querySelectorAll(".toggle-pass");

// Modals
const aboutOpen = document.getElementById("about-open");
const aboutClose = document.getElementById("about-close");
const aboutModal = document.getElementById("modal-about");

const firstModal = document.getElementById("modal-first");
const firstAccept = document.getElementById("first-accept");

const devtoolsModal = document.getElementById("devtools-warning");
const originModal = document.getElementById("origin-lock");

function show(el) { if (el) el.hidden = false; }
function hide(el) { if (el) el.hidden = true; }

const LS_THEME = "cryptoshield-theme";
const LS_ACCEPTED = "cryptoshield-accepted-v1";

function safeLSGet(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}
function safeLSSet(key, val) {
  try { localStorage.setItem(key, val); } catch (_) {}
}

function setStatus(text, type) {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.classList.remove("ok", "err");
  if (type) statusEl.classList.add(type);
}
function setStatusEnc(text, type) {
  if (!statusEncEl) return;
  statusEncEl.textContent = text;
  statusEncEl.classList.remove("ok", "err");
  if (type) statusEncEl.classList.add(type);
}

function setTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = normalized;
  themeButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.theme === normalized));
  safeLSSet(LS_THEME, normalized);
}

// --- Base64 helpers ---
function base64urlToBytes(str) {
  const cleaned = (str || "").replace(/\s+/g, "");
  const b64 = cleaned.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const raw = atob(b64 + pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// --- Crypto primitives (Fernet-compatible) ---
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
function pkcs7Unpad(data) {
  if (data.length === 0) throw new Error("Invalid padding.");
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) throw new Error("Invalid padding.");
  for (let i = data.length - pad; i < data.length; i += 1) {
    if (data[i] !== pad) throw new Error("Invalid padding.");
  }
  return data.slice(0, data.length - pad);
}
function pkcs7Pad(data) {
  const pad = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

async function deriveKeys(passphrase, salt) {
  const pwBytes = new TextEncoder().encode(passphrase);
  const material = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERS },
    material,
    256
  );
  const keyBytes = new Uint8Array(bits); // 32 bytes
  // Fernet: first 16 = signing key, last 16 = encryption key
  return { signingKey: keyBytes.slice(0, 16), encryptionKey: keyBytes.slice(16, 32) };
}

async function verifyHmac(signingKey, data, expected) {
  const key = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  return constantTimeEqual(sig, expected);
}

async function decryptAesCbc(encryptionKey, iv, ciphertext) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, { name: "AES-CBC" }, false, ["decrypt"]);
  const padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext));
  return pkcs7Unpad(padded);
}

async function encryptAesCbc(encryptionKey, iv, plaintextBytes) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const padded = pkcs7Pad(plaintextBytes);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded));
}

function parseFernetTokenRaw(tokenRaw) {
  // raw decoded token: ver(1)+ts(8)+iv(16)+ciphertext+HMAC(32)
  if (tokenRaw.length < 1 + 8 + 16 + 32) throw new Error("Invalid token format.");
  const version = tokenRaw[0];
  if (version !== 0x80) throw new Error("Invalid token version.");
  const ivStart = 1 + 8;
  const hmacStart = tokenRaw.length - 32;
  const iv = tokenRaw.slice(ivStart, ivStart + 16);
  const ciphertext = tokenRaw.slice(ivStart + 16, hmacStart);
  const dataToSign = tokenRaw.slice(0, hmacStart);
  const hmac = tokenRaw.slice(hmacStart);
  return { iv, ciphertext, dataToSign, hmac };
}

// Fernet token bytes are base64url ASCII in Python, so we decode to raw first.
function fernetAsciiToRaw(fernetAsciiBytes) {
  const tokenStr = new TextDecoder().decode(fernetAsciiBytes).trim();
  if (!tokenStr) throw new Error("Invalid token format.");
  return base64urlToBytes(tokenStr);
}

async function decryptFernetRaw(passphrase, fernetAsciiBytes, salt) {
  const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);
  const tokenRaw = fernetAsciiToRaw(fernetAsciiBytes);
  const { iv, ciphertext, dataToSign, hmac } = parseFernetTokenRaw(tokenRaw);

  const ok = await verifyHmac(signingKey, dataToSign, hmac);
  if (!ok) throw new Error("Wrong password or corrupted token.");

  const plaintextBytes = await decryptAesCbc(encryptionKey, iv, ciphertext);
  return new TextDecoder().decode(plaintextBytes);
}

async function encryptFernetToAscii(passphrase, plaintextBytes, salt) {
  const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);

  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await encryptAesCbc(encryptionKey, iv, plaintextBytes);

  const timestamp = Math.floor(Date.now() / 1000);
  let ts = BigInt(timestamp);
  const tsBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) { tsBytes[i] = Number(ts & 0xffn); ts >>= 8n; }

  const dataToSign = new Uint8Array(1 + 8 + 16 + ciphertext.length);
  dataToSign[0] = 0x80;
  dataToSign.set(tsBytes, 1);
  dataToSign.set(iv, 1 + 8);
  dataToSign.set(ciphertext, 1 + 8 + 16);

  const hmacKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, dataToSign));

  const rawToken = new Uint8Array(dataToSign.length + hmac.length);
  rawToken.set(dataToSign);
  rawToken.set(hmac, dataToSign.length);

  // Fernet token (as Python returns) is base64url ASCII
  const tokenStr = bytesToBase64Url(rawToken);
  return new TextEncoder().encode(tokenStr);
}

// --- Payload handling: EXACTLY matches Python encrypt_text/decrypt_text ---
async function decryptPayload(passphrase, payloadStr) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!payloadStr) throw new Error("Token is required.");

  const payloadBytes = base64urlToBytes(payloadStr);

  if (payloadBytes.length < MAGIC.length + SALT_LEN + 10) {
    throw new Error("Invalid token format.");
  }

  for (let i = 0; i < MAGIC.length; i += 1) {
    if (payloadBytes[i] !== MAGIC[i]) throw new Error("Invalid token format.");
  }

  const salt = payloadBytes.slice(MAGIC.length, MAGIC.length + SALT_LEN);
  const fernetAsciiBytes = payloadBytes.slice(MAGIC.length + SALT_LEN);

  try {
    return await decryptFernetRaw(passphrase, fernetAsciiBytes, salt);
  } catch (err) {
    const msg = (err instanceof Error) ? err.message : "Wrong password or corrupted token.";
    // Normalize all crypto failures to the same safe message
    if (String(msg).toLowerCase().includes("padding")) throw new Error("Wrong password or corrupted token.");
    if (String(msg).toLowerCase().includes("version")) throw new Error("Wrong password or corrupted token.");
    throw new Error("Wrong password or corrupted token.");
  }
}

async function encryptPayload(passphrase, plaintext) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!plaintext) throw new Error("Plaintext is required.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const fernetAsciiBytes = await encryptFernetToAscii(passphrase, new TextEncoder().encode(plaintext), salt);

  const payload = new Uint8Array(MAGIC.length + SALT_LEN + fernetAsciiBytes.length);
  payload.set(MAGIC, 0);
  payload.set(salt, MAGIC.length);
  payload.set(fernetAsciiBytes, MAGIC.length + SALT_LEN);

  return bytesToBase64Url(payload);
}

// --- Licensing / origin lock (deterrent) ---
function isLicensedOrigin() {
  // host check
  if (!ALLOWED_HOSTS.includes(location.hostname)) return false;

  // allow localhost anywhere
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") return true;

  // path prefix check on GitHub Pages
  const p = location.pathname || "/";
  return (p === ALLOWED_PATH_PREFIX || p.startsWith(ALLOWED_PATH_PREFIX + "/"));
}

function lockAppUI() {
  [decryptBtn, encryptBtn, copyBtn, copyEncBtn, clearBtn, clearEncBtn].forEach((b) => {
    if (b) b.disabled = true;
  });
}

// --- UI wiring ---
tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    tabPanels.forEach((panel) => { panel.hidden = true; panel.classList.remove("active"); });

    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    const target = document.getElementById(`tab-${btn.dataset.tab}`);
    if (target) {
      target.hidden = false;
      target.classList.add("active");
    }
  });
});

themeButtons.forEach((btn) => btn.addEventListener("click", () => setTheme(btn.dataset.theme)));

togglePassButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "Hide" : "Show";
  });
});

// Encrypt / Decrypt actions
if (decryptBtn) {
  decryptBtn.addEventListener("click", async () => {
    setStatus("Decrypting...", "");
    if (outputBox) outputBox.value = "";
    decryptBtn.disabled = true;

    try {
      const result = await decryptPayload(
        (passphraseDecrypt?.value || "").trim(),
        (tokenInput?.value || "").trim()
      );
      if (outputBox) outputBox.value = result;
      setStatus("Decrypted.", "ok");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Decryption failed.";
      setStatus(msg, "err");
    } finally {
      decryptBtn.disabled = false;
    }
  });
}

if (encryptBtn) {
  encryptBtn.addEventListener("click", async () => {
    setStatusEnc("Encrypting...", "");
    if (tokenOut) tokenOut.value = "";
    encryptBtn.disabled = true;

    try {
      const token = await encryptPayload(
        (passphraseEncrypt?.value || "").trim(),
        (plaintextInput?.value || "").trim()
      );
      if (tokenOut) tokenOut.value = token;
      setStatusEnc("Encrypted.", "ok");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Encryption failed.";
      setStatusEnc(msg, "err");
    } finally {
      encryptBtn.disabled = false;
    }
  });
}

if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    const txt = (outputBox?.value || "").trim();
    if (!txt) return setStatus("Nothing to copy.", "err");
    try {
      await navigator.clipboard.writeText(txt);
      setStatus("Copied to clipboard.", "ok");
    } catch (_) {
      setStatus("Copy failed. Please copy manually.", "err");
    }
  });
}

if (copyEncBtn) {
  copyEncBtn.addEventListener("click", async () => {
    const txt = (tokenOut?.value || "").trim();
    if (!txt) return setStatusEnc("Nothing to copy.", "err");
    try {
      await navigator.clipboard.writeText(txt);
      setStatusEnc("Copied to clipboard.", "ok");
    } catch (_) {
      setStatusEnc("Copy failed. Please copy manually.", "err");
    }
  });
}

if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    if (passphraseDecrypt) passphraseDecrypt.value = "";
    if (tokenInput) tokenInput.value = "";
    if (outputBox) outputBox.value = "";
    setStatus("Cleared.", "");
  });
}

if (clearEncBtn) {
  clearEncBtn.addEventListener("click", () => {
    if (passphraseEncrypt) passphraseEncrypt.value = "";
    if (plaintextInput) plaintextInput.value = "";
    if (tokenOut) tokenOut.value = "";
    setStatusEnc("Cleared.", "");
  });
}

// --- Modals ---
if (aboutOpen && aboutModal) aboutOpen.addEventListener("click", () => show(aboutModal));
if (aboutClose && aboutModal) aboutClose.addEventListener("click", () => hide(aboutModal));
if (aboutModal) {
  aboutModal.addEventListener("click", (e) => {
    if (e.target === aboutModal) hide(aboutModal);
  });
}

if (firstAccept && firstModal) {
  firstAccept.addEventListener("click", () => {
    safeLSSet(LS_ACCEPTED, "yes");
    hide(firstModal);
  });
}

// Show first-run notice once
if (firstModal) {
  const accepted = safeLSGet(LS_ACCEPTED);
  if (accepted !== "yes") show(firstModal);
}

// --- Deterrents (NOT real protection) ---
document.addEventListener("contextmenu", (e) => e.preventDefault());

document.addEventListener("keydown", (e) => {
  const key = String(e.key || "").toLowerCase();
  const ctrl = e.ctrlKey || e.metaKey;

  const blocked =
    key === "f12" ||
    (ctrl && key === "u") ||
    (ctrl && e.shiftKey && ["i", "j", "c"].includes(key));

  if (blocked) {
    e.preventDefault();
    e.stopPropagation();
    if (devtoolsModal) show(devtoolsModal);
  }
}, true);

// Light devtools heuristic (false positives possible)
let devtoolsShown = false;
setInterval(() => {
  const threshold = 220;
  const dw = Math.abs(window.outerWidth - window.innerWidth);
  const dh = Math.abs(window.outerHeight - window.innerHeight);
  const maybeOpen = dw > threshold || dh > threshold;

  if (maybeOpen && !devtoolsShown) {
    devtoolsShown = true;
    if (devtoolsModal) show(devtoolsModal);
  }
  if (!maybeOpen && devtoolsShown) {
    devtoolsShown = false;
    if (devtoolsModal) hide(devtoolsModal);
  }
}, 800);

// --- Boot ---
setTheme(safeLSGet(LS_THEME) === "dark" ? "dark" : "light");

const activeTab = document.querySelector(".tab.active");
if (activeTab) activeTab.click();

// Apply origin lock AFTER boot (so no reference-before-declare issues)
if (!isLicensedOrigin()) {
  lockAppUI();
  setStatus("Unlicensed domain or path. This tool runs only on the official site.", "err");
  setStatusEnc("Unlicensed domain or path. This tool runs only on the official site.", "err");
  show(originModal);
}
