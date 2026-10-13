// viewer proof /p/ — contenitori dal publisher via API, decifrazione locale
var IV_LEN = 12;
var b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
var te = new TextEncoder(), td = new TextDecoder();
var PUBLISHER = "https://simona-pub.dav3.cc";
var q = new URLSearchParams(location.search);
var SLUG = q.get("slug") || "", TOKEN = q.get("t") || "";
function api(file) { return fetch(PUBLISHER + "/api/p/" + SLUG + "/" + file + "?t=" + encodeURIComponent(TOKEN)); }
async function importAes(key) { return crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]); }
async function aesDec(key, data) {
  var k = await importAes(key);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: data.slice(0, IV_LEN) }, k, data.slice(IV_LEN)));
}
async function deriveKek(password, salt, iterations) {
  var base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt, iterations: iterations }, base, 256));
}
var $ = (id) => document.getElementById(id);
var DEK = null, PAYLOAD = null, blobs = [], pageIdx = -1;
function offline() { killLoader(); $("gate").hidden = true; $("offline").hidden = false; }
// link morto: 401/403/404 dal publisher — NON chiedere password (sarebbe fuorviante)
function deadLink() { killLoader(); $("gate").hidden = true; $("invalid").hidden = false; }
async function open(password) {
  var hdrRes;
  try { hdrRes = await api("manifest.enc"); } catch (e) { offline(); throw e; }
  if (!hdrRes.ok) { if (hdrRes.status >= 500) offline(); else deadLink(); return false; }
  var hdr = JSON.parse(td.decode(new Uint8Array(await hdrRes.arrayBuffer())));
  if (hdr.nopw) password = ""; // bozza libera: il segreto è il token nell'URL
  var kek = await deriveKek(password, b64d(hdr.kdf.salt), hdr.kdf.iterations);
  var dek;
  try {
    dek = await aesDec(kek, b64d(hdr.wraps.password));
    PAYLOAD = JSON.parse(td.decode(await aesDec(dek, b64d(hdr.payload))));
  } catch { return false; }
  DEK = dek;
  return true;
}
async function loadPage(i) {
  var p = PAYLOAD.pages[i];
  var res = await api(p.file);
  if (!res.ok) { offline(); return; }
  var dec = await aesDec(DEK, new Uint8Array(await res.arrayBuffer()));
  var off = 0;
  var grid = $("grid");
  for (var n = 0; n < p.items.length; n++) {
    var name = p.items[n];
    var len = new DataView(dec.buffer, dec.byteOffset + off, 4).getUint32(0);
    off += 4;
    var blob = new Blob([dec.slice(off, off + len)], { type: "image/webp" });
    off += len;
    blobs.push({ name: name, url: URL.createObjectURL(blob), full: PAYLOAD.items[name].full });
    var img = new Image();
    img.src = blobs[blobs.length - 1].url;
    img.alt = name;
    img.loading = "lazy";
    img.addEventListener("click", (function (idx) { return function () { lightbox(idx); }; })(blobs.length - 1));
    grid.appendChild(img);
  }
  pageIdx = i;
  $("more").hidden = pageIdx >= PAYLOAD.pages.length - 1;
}
async function lightbox(idx) {
  var b = blobs[idx];
  var img = $("lbimg");
  var cap = $("lbcap");
  if (cap) {
    var meta = PAYLOAD.items[b.name] || {};
    cap.innerHTML = (meta.caption || b.name
      ? '<div class="t">' + (meta.caption || b.name) + "</div>" + (meta.desc ? '<div class="d">' + meta.desc + "</div>" : "")
      : "");
    cap.style.display = cap.innerHTML ? "block" : "none";
  }
  if (!img.dataset.loaded || img.dataset.idx !== String(idx)) {
    var res = await api(b.full);
    if (!res.ok) { offline(); return; }
    var dec = await aesDec(DEK, new Uint8Array(await res.arrayBuffer()));
    img.src = URL.createObjectURL(new Blob([dec], { type: "image/webp" }));
    img.dataset.idx = String(idx);
    img.dataset.loaded = "1";
  }
  $("lb").hidden = false;
  $("lb").dataset.idx = idx;
}
document.addEventListener("keydown", function (e) {
  if ($("lb").hidden) return;
  var n = blobs.length, cur = Number($("lb").dataset.idx);
  if (e.key === "Escape") $("lb").hidden = true;
  if (e.key === "ArrowRight") lightbox((cur + 1) % n);
  if (e.key === "ArrowLeft") lightbox((cur - 1 + n) % n);
});
$("pwform").addEventListener("submit", async function (e) {
  e.preventDefault();
  $("err").hidden = true;
  $("go").disabled = true;
  var ok = await open($("pw").value);
  $("go").disabled = false;
  if (!ok) { if (!$("offline").hidden) return; $("err").hidden = false; return; }
  $("gate").hidden = true;
  killLoader();
  $("gallery").hidden = false;
  var lang = navigator.language && navigator.language.indexOf("it") === 0 ? "it" : "en";
  $("gtitle").textContent = PAYLOAD.title[lang] || PAYLOAD.title.it;
  document.title = $("gtitle").textContent + " — Simona Lascialfari"; // titolo tab = galleria
  await loadPage(0);
});
// bozza libera (nopw): apre automaticamente; altrimenti mostra SOLO ORA il gate
// (niente flash del campo password durante il caricamento)
function showGate(){ var l = $("loading"); if (l) l.remove(); $("gate").hidden = false; $("pw").focus(); }
function killLoader(){ var l = $("loading"); if (l) l.remove(); }
(async function boot(){
  try {
    var r = await api("manifest.enc");
    if (!r.ok) { if (r.status >= 500) offline(); else deadLink(); return; }
    var h = JSON.parse(td.decode(new Uint8Array(await r.arrayBuffer())));
    if (h.nopw) $("pwform").requestSubmit();
    else showGate();
  } catch (e) { offline(); }
})();
$("more").addEventListener("click", function () { loadPage(pageIdx + 1); });
$("close").addEventListener("click", function () { $("lb").hidden = true; });
$("prev").addEventListener("click", function () { var cur = Number($("lb").dataset.idx); lightbox((cur - 1 + blobs.length) % blobs.length); });
$("next").addEventListener("click", function () { var cur = Number($("lb").dataset.idx); lightbox((cur + 1) % blobs.length); });
