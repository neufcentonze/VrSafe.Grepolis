// ==UserScript==
// @name         VrSafe
// @namespace    https://grepolis.com
// @version      2.1.0
// @description  VrSafe
// @author       VrSafe
// @icon         https://vrsafe.duckdns.org/assets/logo.png
// @match        https://*.grepolis.com/game/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @grant        GM_info
// @grant        unsafeWindow
// @connect      vrsafe.duckdns.org
// @connect      raw.githubusercontent.com
// @connect      api.github.com
// @connect      discord.com
// @updateURL    https://vrsafe.duckdns.org/vrsafe.user.js
// @downloadURL  https://vrsafe.duckdns.org/vrsafe.user.js
// @run-at       document-idle
// ==/UserScript==

(function () {
    'use strict';

    // Le build est livré signé (Ed25519) dans une enveloppe JSON. On vérifie la
    // signature avec la clé publique embarquée AVANT d'eval : un serveur compromis
    // sans la clé privée de signature ne peut pas nous faire exécuter de code.
    const BUNDLE_URL = 'https://vrsafe.duckdns.org/u/vrsafe.bundle';
    const TOKEN_KEY = 'vrsafe_auth_key';
    const CACHE_KEY = 'vrsafe_loader_cache';       // enveloppe chiffrée (offline)
    const LASTVER_KEY = 'vrsafe_loader_lastver';   // anti-downgrade / replay
    const CACHE_TTL_MS = 3 * 60 * 60 * 1000;

    // Clé publique Ed25519 (raw, base64url). Correspond à build/signing-key.pem.
    const PUBKEY_B64URL = 'KIXUD56y99BCS2kkVzQSMnUuLyvBAvCINaVCCJsSMyE';

    const cryptoObj = (typeof crypto !== 'undefined' && crypto.subtle) ? crypto
        : ((typeof unsafeWindow !== 'undefined' && unsafeWindow.crypto) ? unsafeWindow.crypto : null);
    const pw = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;

    function getToken() {
        try { return GM_getValue(TOKEN_KEY, '') || ''; } catch (e) { return ''; }
    }

    function b64enc(bytes) {
        let s = ''; const CH = 0x8000;
        for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
        return btoa(s);
    }
    function b64dec(str) {
        const bin = atob(str); const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }
    function b64urlDec(str) {
        let s = str.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        return b64dec(s);
    }

    // Compare "1.30.1" vs "1.9.0" numériquement. -1 : a<b, 0 : =, 1 : a>b.
    function cmpVer(a, b) {
        const pa = String(a || '0').split('.').map(n => parseInt(n, 10) || 0);
        const pb = String(b || '0').split('.').map(n => parseInt(n, 10) || 0);
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
            const x = pa[i] || 0, y = pb[i] || 0;
            if (x > y) return 1;
            if (x < y) return -1;
        }
        return 0;
    }

    // ── Cache chiffré de l'enveloppe (résilience offline) ───────
    async function deriveKey(token) {
        const raw = await cryptoObj.subtle.digest('SHA-256', new TextEncoder().encode(token));
        return cryptoObj.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }
    async function saveCache(token, envelopeText) {
        if (!cryptoObj || !token) return;
        try {
            const key = await deriveKey(token);
            const iv = cryptoObj.getRandomValues(new Uint8Array(12));
            const ct = await cryptoObj.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(envelopeText));
            GM_setValue(CACHE_KEY, JSON.stringify({ iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)), ts: Date.now() }));
        } catch (e) { /* */ }
    }
    async function loadCache(token) {
        if (!cryptoObj || !token) return null;
        try {
            const raw = GM_getValue(CACHE_KEY, '');
            if (!raw) return null;
            const blob = JSON.parse(raw);
            if (!blob.ts || (Date.now() - blob.ts) > CACHE_TTL_MS) return null;
            const key = await deriveKey(token);
            const pt = await cryptoObj.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(blob.iv) }, key, b64dec(blob.ct));
            return new TextDecoder().decode(pt);
        } catch (e) { return null; }
    }

    // ── Vérification de signature ───────────────────────────────
    // Renvoie true/false si on a pu vérifier, ou null si Ed25519 n'est pas supporté
    // par le navigateur (vieux Chrome) → on dégrade sans bloquer (pas de régression).
    async function verifySig(env) {
        if (!cryptoObj || !cryptoObj.subtle) return null;
        let key;
        try {
            key = await cryptoObj.subtle.importKey('raw', b64urlDec(PUBKEY_B64URL), { name: 'Ed25519' }, false, ['verify']);
        } catch (e) {
            return null; // algorithme non supporté ici
        }
        try {
            const msg = new TextEncoder().encode(env.v + '\n' + env.ts + '\n' + env.code);
            return await cryptoObj.subtle.verify('Ed25519', key, b64dec(env.sig), msg);
        } catch (e) {
            return false;
        }
    }

    function run(code) {
        try { eval(code); }
        catch (e) { console.error('[VrSafe]', e); }
    }

    // Vérifie signature + anti-downgrade, injecte le watermark, expose la version,
    // puis eval. Renvoie true si exécuté.
    async function applyEnvelope(env, opts) {
        if (!env || typeof env.code !== 'string' || !env.sig) {
            console.error('[VrSafe] enveloppe invalide'); return false;
        }
        const ok = await verifySig(env);
        if (ok === false) { console.error('[VrSafe] signature invalide → build refusé'); return false; }
        if (ok === null) console.warn('[VrSafe] Ed25519 non supporté ici, exécution sans vérif de signature');

        // Anti-downgrade / replay : on refuse une version strictement plus vieille
        // que la dernière exécutée (un serveur compromis pourrait rejouer un vieux build).
        const last = GM_getValue(LASTVER_KEY, '');
        if (last && cmpVer(env.v, last) < 0) {
            console.error(`[VrSafe] downgrade refusé (${env.v} < ${last})`); return false;
        }

        let code = env.code;
        const wm = env.wm != null ? String(env.wm) : 'anon';
        code = code.split('__VRSAFE_WM__').join(wm);

        try { pw.__vrsafe_build_version = env.v; } catch (e) { /* */ }
        if (ok === true) { try { GM_setValue(LASTVER_KEY, env.v); } catch (e) { /* */ } }
        run(code);
        return true;
    }

    // ── Fetch de l'enveloppe signée ─────────────────────────────
    function fetchBundle(token) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'GET',
                url: BUNDLE_URL,
                // Token en header (plus dans l'URL → n'apparaît pas dans les logs d'accès).
                headers: token
                    ? { 'X-VRSAFE-Key': token, 'Cache-Control': 'no-cache' }
                    : { 'Cache-Control': 'no-cache' },
                onload: (res) => {
                    if (res.status < 200 || res.status >= 300) return reject(new Error('HTTP ' + res.status));
                    const ct = (res.responseHeaders || '').toLowerCase();
                    if (ct && ct.indexOf('content-type') !== -1 && ct.indexOf('json') === -1) {
                        return reject(new Error('bad content-type'));
                    }
                    resolve(res.responseText);
                },
                onerror: () => reject(new Error('network')),
                ontimeout: () => reject(new Error('timeout')),
                timeout: 25000,
            });
        });
    }

    async function boot() {
        const token = getToken();
        try {
            const text = await fetchBundle(token);
            const env = JSON.parse(text);
            const ran = await applyEnvelope(env, { fromCache: false });
            if (ran) { saveCache(token, text); return; }
            throw new Error('envelope rejected');
        } catch (e) {
            // Réseau/serveur KO ou build rejeté → on retombe sur le cache (re-vérifié).
            const cached = await loadCache(token);
            if (cached) {
                try { await applyEnvelope(JSON.parse(cached), { fromCache: true }); }
                catch (e2) { console.error('[VrSafe] cache illisible', e2); }
            } else {
                console.error('[VrSafe] impossible de charger le build', e);
            }
        }
    }

    boot();
})();
