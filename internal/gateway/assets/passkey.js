// Drives the WebAuthn ceremonies for the gateway's interstitial pages.
//
// The server sends PublicKeyCredentialCreationOptions / RequestOptions as JSON
// with base64url fields, which the browser API needs as ArrayBuffers; these
// helpers do that conversion both ways. (navigator.credentials gives back
// ArrayBuffers, which do not survive JSON.stringify.)
(function () {
  "use strict";

  var script = document.currentScript;
  var beginURL = script.dataset.begin;
  var finishURL = script.dataset.finish;
  var csrf = script.dataset.csrf || "";

  var button = document.getElementById("passkey");
  var errBox = document.getElementById("err");

  function fail(message) {
    errBox.textContent = message;
    if (button) {
      button.disabled = false;
    }
  }

  function b64urlToBuffer(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) {
      padded += "=";
    }
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var str = "";
    for (var i = 0; i < bytes.length; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Walk the options object converting the fields WebAuthn requires as buffers.
  function decodeOptions(options) {
    options.challenge = b64urlToBuffer(options.challenge);
    if (options.user && options.user.id) {
      options.user.id = b64urlToBuffer(options.user.id);
    }
    ["allowCredentials", "excludeCredentials"].forEach(function (key) {
      if (Array.isArray(options[key])) {
        options[key] = options[key].map(function (cred) {
          return Object.assign({}, cred, { id: b64urlToBuffer(cred.id) });
        });
      }
    });
    return options;
  }

  function encodeCredential(credential) {
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults
        ? credential.getClientExtensionResults()
        : {},
      response: {
        clientDataJSON: bufferToB64url(response.clientDataJSON),
      },
    };
    if (response.attestationObject) {
      out.response.attestationObject = bufferToB64url(response.attestationObject);
    }
    if (response.authenticatorData) {
      out.response.authenticatorData = bufferToB64url(response.authenticatorData);
    }
    if (response.signature) {
      out.response.signature = bufferToB64url(response.signature);
    }
    if (response.userHandle) {
      out.response.userHandle = bufferToB64url(response.userHandle);
    }
    return out;
  }

  function post(url, body) {
    var headers = { "Content-Type": "application/json" };
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: headers,
      body: body === undefined ? "{}" : JSON.stringify(body),
    });
  }

  async function run() {
    errBox.textContent = "";
    if (button) {
      button.disabled = true;
    }

    if (!window.PublicKeyCredential) {
      fail("This browser does not support passkeys.");
      return;
    }

    try {
      var beginResp = await post(beginURL);
      if (!beginResp.ok) {
        var beginErr = await beginResp.json().catch(function () {
          return {};
        });
        fail(beginErr.error || "Could not start verification.");
        return;
      }

      var options = await beginResp.json();
      // The server wraps options under publicKey, matching the browser API.
      var publicKey = decodeOptions(options.publicKey || options);

      var isRegistration = Boolean(publicKey.user);
      var credential = isRegistration
        ? await navigator.credentials.create({ publicKey: publicKey })
        : await navigator.credentials.get({ publicKey: publicKey });

      if (!credential) {
        fail("No passkey was provided.");
        return;
      }

      var finishResp = await post(finishURL, encodeCredential(credential));
      if (!finishResp.ok) {
        var finishErr = await finishResp.json().catch(function () {
          return {};
        });
        fail(finishErr.error || "Verification failed.");
        return;
      }

      // Reload so the gateway re-evaluates policy with the upgraded session.
      window.location.reload();
    } catch (e) {
      // NotAllowedError is the user cancelling or the ceremony timing out;
      // saying "failed" for that is misleading.
      if (e && e.name === "NotAllowedError") {
        fail("Verification was cancelled or timed out.");
        return;
      }
      fail((e && e.message) || "Verification failed.");
    }
  }

  if (button) {
    button.addEventListener("click", run);
  }
})();
