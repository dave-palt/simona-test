// shell galleria cifrata — WebCrypto, zero dipendenze
const IV_LEN = 12;
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const te = new TextEncoder();
const td = new TextDecoder();

async function importAes(key) {
  return crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function aesDec(key, data) {
  const k = await importAes(key);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: data.slice(0, IV_LEN) }, k, data.slice(IV_LEN));
  return new Uint8Array(pt);
}
async function deriveKek(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256);
  return new Uint8Array(bits);
}

const $ = (id) => document.getElementById(id);
let DEK = null, PAYLOAD = null, blobs = [], pageIdx = -1;

async function open(password) {
  const hdrRes = await fetch("manifest.enc");
  const hdrBytes = new Uint8Array(await hdrRes.arrayBuffer());
  const hdr = JSON.parse(td.decode(hdrBytes));
  if (hdr.nopw) password = ""; // galleria libera: il segreto è l'URL
  const kek = await deriveKek(password, b64d(hdr.kdf.salt), hdr.kdf.iterations);
  let dek;
  try {
    dek = await aesDec(kek, b64d(hdr.wraps.password));
    // prova: il payload si decifra? (garantisce che la password è giusta)
    PAYLOAD = JSON.parse(td.decode(await aesDec(dek, b64d(hdr.payload))));
  } catch {
    return false;
  }
  DEK = dek;
  return true;
}

async function loadPage(i) {
  if (i < 0 || i >= PAYLOAD.pages.length) return; // oltre l'ultima pagina: niente crash
  const p = PAYLOAD.pages[i];
  const res = await fetch(p.file);
  const dec = await aesDec(DEK, new Uint8Array(await res.arrayBuffer()));
  // parse [len][thumb]...
  let off = 0;
  const grid = $("grid");
  for (const name of p.items) {
    const len = new DataView(dec.buffer, dec.byteOffset + off, 4).getUint32(0);
    off += 4;
    const blob = new Blob([dec.slice(off, off + len)], { type: "image/webp" });
    off += len;
    blobs.push({ name, url: URL.createObjectURL(blob), full: PAYLOAD.items[name].full,
      caption: PAYLOAD.items[name].caption, desc: PAYLOAD.items[name].desc });
    const idx = blobs.length - 1; // cattura ORA: il click deve aprire QUESTA foto
    const img = new Image();
    img.src = blobs[idx].url;
    img.alt = PAYLOAD.items[name].caption || name;
    img.title = img.alt;
    img.loading = "lazy";
    img.tabIndex = 0;
    img.addEventListener("click", () => lightbox(idx));
    grid.appendChild(img);
  }
  pageIdx = i;
  $("more").hidden = pageIdx >= PAYLOAD.pages.length - 1;
}

async function lightbox(idx) {
  const b = blobs[idx];
  const img = $("lbimg");
  const cap = $("lbcap");
  if (cap) {
    const meta = PAYLOAD.items[b.name] || {};
    cap.innerHTML = (meta.caption || b.name
      ? '<div class="t">' + (meta.caption || b.name) + "</div>" + (meta.desc ? '<div class="d">' + meta.desc + "</div>" : "")
      : "");
    cap.style.display = cap.innerHTML ? "block" : "none";
  }
  if (!img.dataset.loaded || img.dataset.idx !== String(idx)) {
    // full lazy: decifra solo quando aperta
    const res = await fetch(b.full);
    const dec = await aesDec(DEK, new Uint8Array(await res.arrayBuffer()));
    img.src = URL.createObjectURL(new Blob([dec], { type: "image/webp" }));
    img.dataset.idx = String(idx);
    img.dataset.loaded = "1";
  }
  $("lb").hidden = false;
  $("lb").dataset.idx = idx;
}
document.addEventListener("keydown", (e) => {
  if ($("lb").hidden) return;
  const n = blobs.length;
  const cur = Number($("lb").dataset.idx);
  if (e.key === "Escape") $("lb").hidden = true;
  if (e.key === "ArrowRight") lightbox((cur + 1) % n);
  if (e.key === "ArrowLeft") lightbox((cur - 1 + n) % n);
});

$("pwform").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("err").hidden = true;
  $("go").disabled = true;
  const ok = await open($("pw").value);
  $("go").disabled = false;
  if (!ok) { $("err").hidden = false; return; }
  reveal();
});
// ciò che appare DOPO l'apertura (loader via, titolo, prima pagina)
async function reveal() {
  $("loading").hidden = true;
  $("gate").hidden = true;
  $("gallery").hidden = false;
  const lang = navigator.language?.startsWith("it") ? "it" : "en";
  $("gtitle").textContent = PAYLOAD.title[lang] ?? PAYLOAD.title.it;
  document.title = $("gtitle").textContent + " — Simona Lascialfari"; // titolo tab = galleria
  if (PAYLOAD.dropboxOriginalsUrl) $("dl").href = PAYLOAD.dropboxOriginalsUrl;
  else document.querySelector("#gallery footer")?.remove(); // niente link → niente footer vuoto
  await loadPage(0);
}
// il gate appare SOLO se la password è davvero richiesta: prima leggiamo il
// manifest — nopw → apertura automatica; protetta (o errore rete) → gate
(async () => {
  try {
    const r = await fetch("manifest.enc");
    const hdr = JSON.parse(td.decode(new Uint8Array(await r.arrayBuffer())));
    if (hdr.nopw) {
      if (await open("")) { await reveal(); return; }
    }
  } catch { /* fallthrough: mostra il gate */ }
  $("loading").hidden = true;
  $("gate").hidden = false;
  $("pw")?.focus();
})();
$("more").addEventListener("click", () => loadPage(pageIdx + 1));
$("close").addEventListener("click", () => ($("lb").hidden = true));
$("prev").addEventListener("click", () => {
  const cur = Number($("lb").dataset.idx);
  lightbox((cur - 1 + blobs.length) % blobs.length);
});
$("next").addEventListener("click", () => {
  const cur = Number($("lb").dataset.idx);
  lightbox((cur + 1) % blobs.length);
});
