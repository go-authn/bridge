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
  var button = document.getElementById("passkey-button");
  var status = document.getElementById("passkey-status");
  if (!button) { return; }
  var enroll = button.getAttribute("data-mode") === "enroll";

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

  if (!window.PublicKeyCredential || !navigator.credentials) {
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
  button.disabled = false;

  function failed(e) {
    button.disabled = false;
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

  button.addEventListener("click", function () {
    button.disabled = true;
    say("En attente de votre appareil…", "Waiting for your device…");
    (enroll ? register() : signIn()).catch(failed);
  });
})();
`
