// SPDX-License-Identifier: BSD-3-Clause

package app

// passkeyJS is the browser half of the local login and of enrolment: it asks
// this provider for options, hands them to navigator.credentials, and posts
// the answer back. It is served from this origin (the pages' script-src is
// 'self'), holds no secret, and is the same for everybody.
//
// ⛔ The invitation token is read from location.hash, posted in a JSON body
// and removed from the address bar at once: it was never in a request line,
// so it is in no log, and it is not in the history either.
const passkeyJS = `"use strict";
(function () {
  // The page an institution's answer ends at carries one form, which this
  // script posts from this origin (account.go, accountOpen).
  var auto = document.getElementById("auto-submit");
  if (auto) { auto.submit(); return; }
  var button = document.getElementById("passkey-button");
  var status = document.getElementById("passkey-status");
  var account = document.getElementById("account");
  if (!button && !account) { return; }
  // mode: "login" (the default), "enroll" (an invitation), "stepup" and "add"
  // (the account page, before and after the confirmation).
  var mode = button ? (button.getAttribute("data-mode") || "login") : "account";
  var enroll = mode === "enroll";

  function say(fr, en) { status.textContent = fr + " / " + en; }

  function dec(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) { s += "="; }
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out.buffer;
  }
  function enc(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error"
    }).then(function (r) {
      return r.text().then(function (t) {
        if (!r.ok) { throw new Error(t || String(r.status)); }
        return JSON.parse(t);
      });
    });
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return { type: c.type, id: dec(c.id), transports: c.transports };
    });
  }

  if (button && (!window.PublicKeyCredential || !navigator.credentials)) {
    say("Ce navigateur ne gère pas les clés d'accès.", "This browser does not support passkeys.");
    return;
  }

  var token = "";
  if (enroll) {
    token = location.hash.replace(/^#/, "");
    history.replaceState(null, "", location.pathname);
    if (!token) {
      say("Ouvrez le lien d'invitation en entier.", "Open the whole invitation link.");
      return;
    }
  }
  if (button) { button.disabled = false; }

  function failed(e) {
    if (button) { button.disabled = false; }
    if (e && e.name === "NotAllowedError") {
      say("Annulé, ou le délai est dépassé.", "Cancelled, or timed out.");
    } else if (e && e.name === "InvalidStateError") {
      say("Cet appareil a déjà une clé d'accès pour ce compte.", "This device already has a passkey for this account.");
    } else {
      say("Échec : " + (e && e.message ? e.message : e), "Failed.");
    }
  }

  function register() {
    return post("enroll/begin", { token: token }).then(function (b) {
      var pk = b.publicKey;
      pk.challenge = dec(pk.challenge);
      pk.user.id = dec(pk.user.id);
      pk.excludeCredentials = descriptors(pk.excludeCredentials);
      return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
        var transports = cred.response.getTransports ? cred.response.getTransports() : [];
        return post("enroll/finish", {
          handle: b.handle,
          id: enc(cred.rawId),
          clientDataJSON: enc(cred.response.clientDataJSON),
          attestationObject: enc(cred.response.attestationObject),
          transports: transports
        });
      });
    }).then(function () {
      button.disabled = true;
      say("Clé d'accès enregistrée. Vous pouvez fermer cette page.", "Passkey registered. You can close this page.");
    });
  }

  function signIn() {
    var form = document.getElementById("passkey-login");
    return post("login/begin", { csrf: form.getAttribute("data-csrf") }).then(function (b) {
      var pk = b.publicKey;
      pk.challenge = dec(pk.challenge);
      pk.allowCredentials = descriptors(pk.allowCredentials);
      return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
        var r = cred.response;
        if (!r.userHandle) { throw new Error("no user handle"); }
        form.elements.handle.value = b.handle;
        form.elements.id.value = enc(cred.rawId);
        form.elements.clientDataJSON.value = enc(r.clientDataJSON);
        form.elements.authenticatorData.value = enc(r.authenticatorData);
        form.elements.signature.value = enc(r.signature);
        form.elements.userHandle.value = enc(r.userHandle);
        // A real form post: the redirect that follows is the browser's, and the
        // page's form-action decides where it may go.
        form.submit();
      });
    });
  }

  // The account page. Its requests carry the page's CSRF token, which the
  // server derives from the session; the session itself is an HttpOnly cookie
  // this script cannot read, and nothing is kept in the browser's storage.
  function csrf() { return account.getAttribute("data-csrf"); }

  function stepUp() {
    return post("account/stepup/begin", {}).then(function (b) {
      var pk = b.publicKey;
      pk.challenge = dec(pk.challenge);
      pk.allowCredentials = descriptors(pk.allowCredentials);
      return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
        var r = cred.response;
        if (!r.userHandle) { throw new Error("no user handle"); }
        return post("account/stepup/finish", {
          handle: b.handle,
          id: enc(cred.rawId),
          clientDataJSON: enc(r.clientDataJSON),
          authenticatorData: enc(r.authenticatorData),
          signature: enc(r.signature),
          userHandle: enc(r.userHandle)
        });
      });
    }).then(function () { location.reload(); });
  }

  function addKey() {
    return post("account/add/begin", { csrf: csrf() }).then(function (b) {
      var pk = b.publicKey;
      pk.challenge = dec(pk.challenge);
      pk.user.id = dec(pk.user.id);
      pk.excludeCredentials = descriptors(pk.excludeCredentials);
      return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
        var transports = cred.response.getTransports ? cred.response.getTransports() : [];
        return post("account/add/finish", {
          csrf: csrf(),
          handle: b.handle,
          id: enc(cred.rawId),
          clientDataJSON: enc(cred.response.clientDataJSON),
          attestationObject: enc(cred.response.attestationObject),
          transports: transports
        });
      });
    }).then(function () { location.reload(); });
  }

  if (account) {
    // Every other button names its endpoint (data-post), its body (data-json),
    // and perhaps a field read from an input (data-from, data-field).
    var posts = account.querySelectorAll("[data-post]");
    Array.prototype.forEach.call(posts, function (b) {
      b.addEventListener("click", function () {
        var q = b.getAttribute("data-confirm");
        if (q && !window.confirm(q)) { return; }
        var body = JSON.parse(b.getAttribute("data-json") || "{}");
        body.csrf = csrf();
        if (b.getAttribute("data-from")) {
          body[b.getAttribute("data-field")] = document.getElementById(b.getAttribute("data-from")).value;
        }
        b.disabled = true;
        post(b.getAttribute("data-post"), body)
          .then(function () { location.reload(); }).catch(function (e) { b.disabled = false; failed(e); });
      });
    });
  }

  if (button) {
    button.addEventListener("click", function () {
      button.disabled = true;
      say("En attente de votre appareil…", "Waiting for your device…");
      var run = mode === "enroll" ? register : mode === "stepup" ? stepUp : mode === "add" ? addKey : signIn;
      run().catch(failed);
    });
  }
})();
`
