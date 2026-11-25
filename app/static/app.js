// CSP forbids inline scripts/handlers, so everything lives here.
// Loaded in <head> (synchronously) so the saved theme applies before first paint.

// ---- theme: auto (follows OS) -> manual light/dark, remembered in localStorage ----
(function () {
  var root = document.documentElement;
  function stored() { try { return localStorage.getItem("theme"); } catch (e) { return null; } }
  function save(v) { try { localStorage.setItem("theme", v); } catch (e) {} }
  var t = stored();
  if (t === "light" || t === "dark") root.setAttribute("data-theme", t);

  function isDark() {
    var t = root.getAttribute("data-theme");
    if (t) return t === "dark";
    return window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches;
  }
  function paint(btn) {
    var icon = isDark() ? "☀" : "☾";  // sun / moon
    if (btn.hasAttribute("data-label")) {
      btn.innerHTML = "";
      var i = document.createElement("span"); i.textContent = icon; i.style.cssText = "width:18px;text-align:center;font-size:17px;line-height:1";
      var l = document.createElement("span"); l.className = "lbl"; l.textContent = isDark() ? "Light mode" : "Dark mode";
      btn.appendChild(i); btn.appendChild(l);
    } else btn.textContent = icon;
    var label = isDark() ? "Switch to light mode" : "Switch to dark mode";
    btn.title = label; btn.setAttribute("aria-label", label);
  }
  document.addEventListener("DOMContentLoaded", function () {
    var picks = document.querySelectorAll("[data-theme-set]");
    if (picks.length) {
      var mark = function () {
        var cur = root.getAttribute("data-theme") || "auto";
        picks.forEach(function (b) {
          var on = b.getAttribute("data-theme-set") === cur;
          b.classList.toggle("on", on); b.setAttribute("aria-pressed", on ? "true" : "false");
        });
      };
      picks.forEach(function (b) {
        b.addEventListener("click", function () {
          var v = b.getAttribute("data-theme-set");
          if (v === "auto") { root.removeAttribute("data-theme"); try { localStorage.removeItem("theme"); } catch (e) {} }
          else { root.setAttribute("data-theme", v); save(v); }
          mark();
        });
      });
      mark();
      return;
    }
    var btn = document.getElementById("theme-toggle");
    var created = !btn;
    if (created) { btn = document.createElement("button"); btn.id = "theme-toggle"; btn.type = "button"; btn.className = "floating"; }
    paint(btn);
    btn.addEventListener("click", function () {
      var next = isDark() ? "light" : "dark";
      root.setAttribute("data-theme", next);
      save(next);
      paint(btn);
    });
    if (created) document.body.appendChild(btn);
  });
})();

// ---- confirmation prompts ----
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !confirm(msg)) e.preventDefault();
});

// ---- live filter for tables and lists: <input data-filter="#tableid"> ----
document.addEventListener("input", function (e) {
  var sel = e.target.getAttribute && e.target.getAttribute("data-filter");
  if (!sel) return;
  var q = e.target.value.trim().toLowerCase();
  document.querySelectorAll(sel + " tbody tr, " + sel + " > li").forEach(function (tr) {
    tr.style.display = tr.textContent.toLowerCase().indexOf(q) === -1 ? "none" : "";
  });
});

// ---- passkeys (WebAuthn) ----
(function () {
  function toBuf(s) {  // base64url -> ArrayBuffer
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a.buffer;
  }
  function toB64u(buf) {  // ArrayBuffer -> base64url
    var a = new Uint8Array(buf), s = "";
    for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function csrf() {
    var el = document.querySelector("[data-csrf]");
    return el ? el.getAttribute("data-csrf") : "";
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok || j.ok === false) throw new Error(j.error || ("HTTP " + r.status));
        return j;
      });
    });
  }
  function say(text, isErr) {
    var m = document.getElementById("pk-msg");
    if (!m) return;
    m.textContent = text || "";
    m.className = "msg" + (isErr ? " err" : "");
  }
  // Only one passkey request can run at a time. A password manager extension that is locked (Bitwarden,
  // 1Password...) can leave its prompt pending forever, and then every later attempt fails until the page is
  // reloaded. So each attempt cancels the one before it, and a cancelled attempt stays quiet.
  var pending = null;
  function start() {
    if (pending) { try { pending.abort(); } catch (e) {} }
    pending = window.AbortController ? new AbortController() : null;
    return pending;
  }
  function current(ac) { return !ac || ac === pending; }
  function fail(e, ac) {
    if (!current(ac)) return;   // replaced by a newer attempt
    pending = null;
    if (e && (e.name === "NotAllowedError" || e.name === "AbortError"))
      say("Cancelled or timed out. If your password manager was locked, unlock it and try again.", true);
    else if (e && e.name === "InvalidStateError") say("This device already has a passkey for this site.", true);
    else say((e && e.message) || "Something went wrong.", true);
  }
  function supported() {
    if (window.PublicKeyCredential && navigator.credentials) return true;
    say("This browser or page can't use passkeys. Open the site over HTTPS on its real domain.", true);
    return false;
  }

  function register() {
    if (!supported()) return;
    var nameEl = document.getElementById("pk-name");
    var ac = start();
    say("Follow the prompt on your device…");
    post("/passkeys/register/options").then(function (o) {
      o.challenge = toBuf(o.challenge);
      o.user.id = toBuf(o.user.id);
      (o.excludeCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
      return navigator.credentials.create(ac ? { publicKey: o, signal: ac.signal } : { publicKey: o });
    }).then(function (c) {
      var r = c.response;
      return post("/passkeys/register/verify", {
        name: nameEl ? nameEl.value : "",
        credential: {
          id: c.id, rawId: toB64u(c.rawId), type: c.type,
          authenticatorAttachment: c.authenticatorAttachment || null,
          response: {
            clientDataJSON: toB64u(r.clientDataJSON),
            attestationObject: toB64u(r.attestationObject),
            transports: r.getTransports ? r.getTransports() : []
          }
        }
      });
    }).then(function () { location.reload(); }).catch(function (e) { fail(e, ac); });
  }

  function login() {
    if (!supported()) return;
    var ac = start();
    say("Follow the prompt on your device…");
    post("/passkeys/login/options").then(function (o) {
      o.challenge = toBuf(o.challenge);
      (o.allowCredentials || []).forEach(function (c) { c.id = toBuf(c.id); });
      return navigator.credentials.get(ac ? { publicKey: o, signal: ac.signal } : { publicKey: o });
    }).then(function (c) {
      var r = c.response;
      return post("/passkeys/login/verify", {
        credential: {
          id: c.id, rawId: toB64u(c.rawId), type: c.type,
          authenticatorAttachment: c.authenticatorAttachment || null,
          response: {
            clientDataJSON: toB64u(r.clientDataJSON),
            authenticatorData: toB64u(r.authenticatorData),
            signature: toB64u(r.signature),
            userHandle: r.userHandle ? toB64u(r.userHandle) : null
          }
        }
      });
    }).then(function (j) { location.href = j.next || "/"; }).catch(function (e) { fail(e, ac); });
  }

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-pk-register]")) register();
    else if (e.target.closest("[data-pk-login]")) login();
  });
})();

// ---- messages (toasts): success messages leave by themselves; errors stay, with a close button ----
function fadeOut(el, delay) {
  setTimeout(function () {
    el.classList.add("leaving");
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 400);
  }, delay);
}
// leave after `delay`, but not while the mouse is over the toast (time to finish reading)
function autoDismiss(el, delay) {
  var timer = setTimeout(go, delay);
  function go() { fadeOut(el, 0); }
  el.addEventListener("mouseenter", function () { clearTimeout(timer); });
  el.addEventListener("mouseleave", function () { clearTimeout(timer); timer = setTimeout(go, 2500); });
}
function addClose(el) {
  if (el.querySelector(".flash-x")) return;
  var b = document.createElement("button");
  b.type = "button";
  b.className = "flash-x";
  b.setAttribute("aria-label", "Dismiss");
  b.textContent = "×";
  b.addEventListener("click", function () { fadeOut(el, 0); });
  el.appendChild(b);
}
document.addEventListener("DOMContentLoaded", function () {
  // only one-time messages (data-flash); permanent notices about a state that needs fixing stay put
  document.querySelectorAll(".flash[data-flash]").forEach(function (el) {
    if (el.classList.contains("ok")) autoDismiss(el, 5000);
    else addClose(el);
  });
});


// ---- idle sign-out: report real activity, warn a minute before the session ends ----
document.addEventListener("DOMContentLoaded", function () {
  if (!document.querySelector('form[action$="/logout"]')) return;   // only when signed in
  var csrfEl = document.querySelector('input[name="csrf"]');
  var lastPing = Date.now(), warn = null, deadline = null, tick = null;

  function ping() {
    lastPing = Date.now();
    fetch("/session/ping", { method: "POST", credentials: "same-origin",
                             headers: { "X-CSRF-Token": csrfEl ? csrfEl.value : "" } })
      .then(function (r) { if (r.status === 401) location.href = "/login"; else hideWarn(); })
      .catch(function () {});
  }
  ["keydown", "mousedown", "mousemove", "touchstart", "wheel"].forEach(function (ev) {
    document.addEventListener(ev, function () {
      if (Date.now() - lastPing > 60000) ping();   // at most once a minute
    }, { passive: true });
  });

  function hideWarn() {
    if (warn) { fadeOut(warn, 0); warn = null; }
    if (tick) { clearInterval(tick); tick = null; }
    deadline = null;
  }
  function showWarn(seconds) {
    deadline = Date.now() + seconds * 1000;
    if (!warn) {
      warn = document.createElement("div");
      warn.className = "flash warn idle-warn";   // a heads-up, not an error
      warn.setAttribute("role", "alert");
      var text = document.createElement("span");
      var btn = document.createElement("button");
      btn.type = "button"; btn.className = "btn"; btn.textContent = "Stay signed in";
      btn.addEventListener("click", ping);
      warn.appendChild(text); warn.appendChild(btn);
      var holder = document.getElementById("toasts");
      if (holder) holder.insertBefore(warn, holder.firstChild);
      tick = setInterval(render, 1000);
    }
    render();
  }
  function render() {
    if (!warn || !deadline) return;
    var s = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    warn.firstChild.textContent = "You'll be signed out in " + s + " s because there was no activity. ";
    if (s <= 0 && !ending) { ending = true; setTimeout(check, 1500); }
  }
  // The server decides: the page goes to the sign-in page only once the server reports the session ended
  // (activity in another tab may have kept it alive).
  var ending = false;
  function check() {
    fetch("/session/status", { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        ending = false;
        if (!s.signed_in) { location.href = "/login"; return; }
        if (s.left === null || s.left === undefined) return;   // idle sign-out is off
        if (s.left <= 0) { ending = true; setTimeout(check, 1500); }   // the next check signs out
        else if (s.left <= 60) showWarn(s.left);
        else hideWarn();
      })
      .catch(function () { ending = false; });
  }
  setInterval(check, 15000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) check(); });
});

// ---- copy buttons: <button data-copy="#selector"> ----
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy]");
  if (!b) return;
  var src = document.querySelector(b.getAttribute("data-copy"));
  if (!src || !navigator.clipboard) return;
  navigator.clipboard.writeText(src.textContent.trim()).then(function () {
    var t = b.textContent; b.textContent = "copied"; setTimeout(function () { b.textContent = t; }, 1200);
  });
});

// ---- after "Restart container": live status card (?restarting=1) ----
(function () {
  if (new URLSearchParams(location.search).get("restarting") !== "1") return;
  document.addEventListener("DOMContentLoaded", function () {
    var holder = document.getElementById("toasts");
    if (!holder) return;
    var card = document.createElement("div");
    card.className = "flash wait";
    card.setAttribute("role", "status");
    card.textContent = "Fail2ban container restarting…";
    holder.insertBefore(card, holder.firstChild);
    // drop only the marker, so a reload doesn't start watching again (keep ?path=... and the like)
    var params = new URLSearchParams(location.search);
    params.delete("restarting");
    var rest = params.toString();
    history.replaceState(null, "", location.pathname + (rest ? "?" + rest : "") + location.hash);
    var start = Date.now(), done = false;
    function secs() { return Math.round((Date.now() - start) / 1000); }
    function finish(cls, text) {
      done = true; card.className = "flash " + cls; card.textContent = text;
      if (cls === "ok") autoDismiss(card, 5000); else addClose(card);
      document.dispatchEvent(new CustomEvent("f2b:refresh"));
    }
    function poll() {
      fetch("/fail2ban/status", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          if (s.up && document.body.hasAttribute("data-f2b-starting")) {
            // this page was drawn while Fail2ban was down: draw it again now that it answers
            done = true; card.className = "flash ok"; card.textContent = "Fail2ban is up again (" + secs() + " s).";
            setTimeout(function () { location.reload(); }, 600);
          }
          else if (s.up) finish("ok", "Fail2ban is up again (" + secs() + " s): version " + s.version + ", " + s.jails + " jail" + (s.jails === 1 ? "" : "s") + " running.");
          else card.textContent = "Fail2ban is starting… (" + secs() + " s" + (s.container ? ", container " + s.container : "") + ")";
        })
        .catch(function () {})
        .then(function () {
          if (done) return;
          if (secs() > 90) finish("error", "Fail2ban hasn't answered 90 seconds after the restart. Check its log on the host (docker logs). A configuration error stops it from starting.");
          else setTimeout(poll, 1500);
        });
    }
    setTimeout(poll, 1500);
  });
})();

// ---- status strip (every page) and dashboard tiles: one status request, refreshed while the page is open ----
document.addEventListener("DOMContentLoaded", function () {
  var strip = document.getElementById("strip");
  if (!strip) return;
  function $(id) { return document.getElementById(id); }
  function text(id, t) { var el = $(id); if (el) el.textContent = t; }
  function tag(id, cls, t) { var el = $(id); if (el) { el.className = "tag " + cls; el.textContent = t; } }
  var busy = false;
  function refresh() {
    if (busy || document.hidden) return;
    busy = true;
    fetch(strip.getAttribute("data-status"), { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { if (r.status === 401) { location.href = "/login"; throw new Error("signed out"); } return r.json(); })
      .then(function (s) {
        var dot = $("st-dot");
        if (s.starting !== null && s.starting !== undefined) {
          if (dot) dot.className = "dot warn";
          text("st-f2b", "Fail2ban starting");
          text("st-f2b-sub", "container started " + s.starting + " s ago");
          setTimeout(refresh, 3000);   // check again soon, not in 30 s
        } else if (s.container_error || s.error) {
          if (dot) dot.className = "dot bad";
          text("st-f2b", s.container_error ? "Fail2ban unreachable" : (s.container === "running" ? "Fail2ban not answering" : "Fail2ban " + (s.container || "down")));
          text("st-f2b-sub", "");
          var sub = $("st-f2b-sub"); if (sub) sub.title = s.container_error || s.error;
        } else {
          if (dot) dot.className = "dot ok";
          text("st-f2b", "Fail2ban running");
          // the version, and whether it's the newest Fail2ban release
          var sub = $("st-f2b-sub");
          if (sub) {
            sub.textContent = "v" + s.version + " ";
            var newer = function (a, b) {   // is a newer than b?
              var x = String(a).split(".").map(Number), y = String(b).split(".").map(Number);
              for (var k = 0; k < 3; k++) { if ((x[k] || 0) !== (y[k] || 0)) return (x[k] || 0) > (y[k] || 0); }
              return false;
            };
            if (s.latest) {
              var vt = document.createElement("span");
              if (newer(s.latest, s.version)) { vt.className = "tag warn"; vt.textContent = s.latest + " available"; vt.title = "Fail2ban " + s.latest + " is out; pull the newer image of your Fail2ban container to update"; }
              else { vt.className = "tag ok"; vt.textContent = "latest"; vt.title = "Fail2ban " + s.version + " is the newest release"; }
              sub.appendChild(vt);
            }
          }
        }
        var cfg;
        if (s.config_ok === true) cfg = ["ok", s.config_warnings ? "valid · " + s.config_warnings + " warning" + (s.config_warnings === 1 ? "" : "s") : "valid"];
        else if (s.config_ok === false) cfg = ["bad", s.config_errors + (s.config_errors === 1 ? " problem" : " problems")];
        else cfg = ["mut", "not checked"];
        tag("st-config", cfg[0], cfg[1]);
        tag("dash-config", cfg[0], cfg[1]);
        // public IP, with a warning when this server's own address is banned
        var banned = s.public_ip_banned && s.public_ip_banned.length;
        var pipText = s.public_ip || (s.public_ip_error === "off" ? "off" : "unknown");
        text("st-pip", pipText + (banned ? " · banned in " + s.public_ip_banned.join(", ") : ""));
        var pw = $("st-pip-wrap");
        if (pw) { pw.style.color = banned ? "var(--bad)" : ""; pw.hidden = s.public_ip_error === "off"; }
        text("st-time", "Updated " + s.checked);
        var pend = $("dash-pending");
        if (pend) { pend.hidden = !s.pending; if (s.pending) text("dash-pending-at", s.pending.toLowerCase()); }
      })
      .catch(function () { var dot = $("st-dot"); if (dot) dot.className = "dot"; text("st-f2b-sub", "status unavailable"); })
      .then(function () { busy = false; });
  }
  refresh();
  setInterval(refresh, 30000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });
  document.addEventListener("f2b:refresh", refresh);
});

// ---- phones: the search button in the top bar shows or hides the IP lookup box ----
document.addEventListener("click", function (e) {
  var b = e.target.closest && e.target.closest("#msearch");
  if (!b) return;
  var bar = b.closest(".topin"), open = !bar.classList.contains("searching");
  bar.classList.toggle("searching", open);
  b.setAttribute("aria-expanded", open ? "true" : "false");
  // the "( / )" keyboard hint means nothing on a phone
  if (open) { var s = document.getElementById("top-lookup"); if (s) { s.placeholder = "Look up an IP"; s.focus(); } }
});
document.addEventListener("keydown", function (e) {
  if (e.key !== "Escape") return;
  var bar = document.querySelector(".topin.searching");
  if (!bar) return;
  bar.classList.remove("searching");
  var b = document.getElementById("msearch"); if (b) { b.setAttribute("aria-expanded", "false"); b.focus(); }
});

// ---- "/" jumps to the IP lookup in the top bar; Escape closes the user menu ----
document.addEventListener("keydown", function (e) {
  var t = e.target, typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
  if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
    var s = document.getElementById("top-lookup");
    if (s && s.offsetParent !== null) { e.preventDefault(); s.focus(); }
  }
  if (e.key === "Escape") document.querySelectorAll("details.usermenu[open]").forEach(function (d) { d.open = false; });
});
document.addEventListener("click", function (e) {
  document.querySelectorAll("details.usermenu[open]").forEach(function (d) { if (!d.contains(e.target)) d.open = false; });
});

// ---- filter tester (fail2ban-regex) on a filter's editor page ----
document.addEventListener("DOMContentLoaded", function () {
  var box = document.getElementById("tester");
  if (!box) return;
  var run = document.getElementById("t-run"), msg = document.getElementById("t-msg");
  run.addEventListener("click", function () {
    var ta = document.querySelector("textarea[data-editor]");
    var log = document.getElementById("t-log");
    msg.className = "msg"; msg.textContent = "Running…"; run.disabled = true;
    fetch(box.getAttribute("data-url"), {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": box.getAttribute("data-csrf") },
      body: JSON.stringify({ path: box.getAttribute("data-path"), content: ta ? ta.value : "",
                             sample: document.getElementById("t-sample").value, logfile: log ? log.value : "" })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (j.error) { msg.className = "msg err"; msg.textContent = j.error; return; }
      msg.textContent = "";
      document.getElementById("t-out").hidden = false;
      document.getElementById("t-pre").textContent = j.output || "";
      var sum = document.getElementById("t-sum");
      sum.innerHTML = "";
      if (j.summary) {
        [["matched", j.summary.matched ? "ok" : "bad"], ["missed", j.summary.missed ? "warn" : "mut"], ["ignored", "mut"], ["lines", "mut"]].forEach(function (p) {
          var t = document.createElement("span"); t.className = "tag " + p[1]; t.textContent = j.summary[p[0]] + " " + p[0]; sum.appendChild(t);
        });
      } else if (!j.ok) { msg.className = "msg err"; msg.textContent = "fail2ban-regex reported an error (see below)."; }
    }).catch(function (e) { msg.className = "msg err"; msg.textContent = String(e); })
      .then(function () { run.disabled = false; });
  });
});

// ---- dashboard chart: switch between 24 h, 7 days and 30 days (data is in the page, no request) ----
document.addEventListener("DOMContentLoaded", function () {
  var chart = document.getElementById("chart");
  if (!chart) return;
  var series;
  try { series = JSON.parse(chart.getAttribute("data-series")); } catch (e) { return; }
  var KEY = "f2bChartRange";
  function show(key) {
    var s = series && series[key];
    if (!s) return;
    var bars = document.getElementById("chart-bars"), axis = document.getElementById("chart-axis");
    bars.innerHTML = ""; axis.innerHTML = "";
    s.bars.forEach(function (b) {
      var i = document.createElement("i");
      if (b.hi) i.className = "hi";
      i.style.height = Math.max(b.pct, 2) + "%";
      i.title = b.label + ": " + b.n + " ban" + (b.n === 1 ? "" : "s");
      bars.appendChild(i);
    });
    s.ticks.forEach(function (t) { var sp = document.createElement("span"); sp.textContent = t; axis.appendChild(sp); });
    document.getElementById("chart-total").textContent = s.total;
    document.getElementById("chart-ips").textContent = s.ips;
    var bw = document.getElementById("chart-busiest-w");
    bw.hidden = !s.busiest;
    document.getElementById("chart-busiest").textContent = s.busiest || "";
    document.querySelectorAll(".seg [data-range]").forEach(function (b) { b.classList.toggle("on", b.getAttribute("data-range") === key); });
    try { localStorage.setItem(KEY, key); } catch (e) {}
  }
  document.querySelectorAll(".seg [data-range]").forEach(function (b) {
    b.addEventListener("click", function () { show(b.getAttribute("data-range")); });
  });
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  if (saved && saved !== "7d") show(saved);
});

// ---- dashboard: put each card in whichever column is shorter, so neither column leaves a big gap ----
// Banned now stays top left and Jails top right; on phones (one column) the cards keep their fixed order.
document.addEventListener("DOMContentLoaded", function () {
  var box = document.getElementById("dash-cards");
  if (!box) return;
  var cols = Array.prototype.filter.call(box.children, function (c) { return c.classList.contains("dcol"); });
  if (cols.length !== 2) return;
  var cards = Array.prototype.slice.call(box.querySelectorAll("[data-card]"))
    .sort(function (a, b) { return a.getAttribute("data-card") - b.getAttribute("data-card"); });
  function place() {
    var twoCols = getComputedStyle(box).gridTemplateColumns.trim().split(/\s+/).length > 1;
    var held = document.createDocumentFragment();   // take every card out first, so heights are measured fairly
    cards.forEach(function (c) { held.appendChild(c); });
    cards.forEach(function (c) {
      var pin = c.getAttribute("data-pin");
      var target;
      if (!twoCols) target = cols[0];
      else if (pin === "left") target = cols[0];
      else if (pin === "right") target = cols[1];
      else target = cols[0].offsetHeight <= cols[1].offsetHeight ? cols[0] : cols[1];
      target.appendChild(c);
    });
  }
  place();
  var t = null;
  window.addEventListener("resize", function () { clearTimeout(t); t = setTimeout(place, 150); });
});

// ---- Activity: filter the ban history by text, jail, time range and "banned now" ----
document.addEventListener("DOMContentLoaded", function () {
  var box = document.getElementById("ban-filters");
  var table = document.getElementById("ban-table");
  if (!box || !table) return;
  var q = document.getElementById("hf-q"), jail = document.getElementById("hf-jail");
  var onlyNow = document.getElementById("hf-now"), sum = document.getElementById("hf-sum");
  var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-ts]"));
  var days = parseInt((box.querySelector(".seg .on") || {}).getAttribute ? box.querySelector(".seg .on").getAttribute("data-range") : "30", 10);
  function apply() {
    var text = q.value.trim().toLowerCase(), j = jail.value, cutoff = Date.now() / 1000 - days * 86400;
    var n = 0, ips = {};
    rows.forEach(function (tr) {
      var show = +tr.getAttribute("data-ts") >= cutoff &&
                 (!j || tr.getAttribute("data-jail") === j) &&
                 (!onlyNow.checked || tr.hasAttribute("data-now")) &&
                 (!text || tr.textContent.toLowerCase().indexOf(text) !== -1);
      tr.style.display = show ? "" : "none";
      if (show) { n++; ips[tr.getAttribute("data-ip")] = 1; }
    });
    var k = Object.keys(ips).length;
    var range = days === 1 ? "the last 24 hours" : "the last " + days + " days";
    sum.textContent = n + " ban" + (n === 1 ? "" : "s") + " from " + k + " IP" + (k === 1 ? "" : "s") + " in " + range +
      (j ? " · jail " + j : "") + (onlyNow.checked ? " · banned now" : "") + (text ? " · matching “" + q.value.trim() + "”" : "");
  }
  box.querySelectorAll(".seg [data-range]").forEach(function (b) {
    b.addEventListener("click", function () {
      days = parseInt(b.getAttribute("data-range"), 10);
      box.querySelectorAll(".seg [data-range]").forEach(function (x) { x.classList.toggle("on", x === b); });
      apply();
    });
  });
  q.addEventListener("input", apply);
  jail.addEventListener("change", apply);
  onlyNow.addEventListener("change", apply);
  apply();
});

// ---- AbuseIPDB: open an IP's report there (button next to an input: data-abuseipdb="#inputId") ----
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-abuseipdb]");
  if (!b) return;
  var input = document.querySelector(b.getAttribute("data-abuseipdb"));
  var msg = b.closest("form") && b.closest("form").parentNode.querySelector(".msg");
  var ip = input ? input.value.trim() : "";
  var ok = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || (/^[0-9a-fA-F:]+$/.test(ip) && ip.indexOf(":") !== -1);
  if (!ok) {
    if (msg) { msg.className = "msg err"; msg.textContent = ip ? "That isn't an IP address." : "Enter an IP address first."; }
    if (input) input.focus();
    return;
  }
  if (msg) { msg.className = "msg"; msg.textContent = ""; }
  window.open("https://www.abuseipdb.com/check/" + ip, "_blank", "noopener,noreferrer");   // ip is validated above
});

// ---- AbuseIPDB score next to IPs, and the facts on the lookup page (data from /ipinfo, cached on the server) ----
document.addEventListener("DOMContentLoaded", function () {
  var tags = Array.prototype.slice.call(document.querySelectorAll("[data-abuse-ip]"));
  var facts = document.getElementById("ip-facts");
  var ips = [];
  tags.forEach(function (t) { var ip = t.getAttribute("data-abuse-ip"); if (ips.indexOf(ip) === -1) ips.push(ip); });
  if (facts && facts.querySelector("[data-f]") && ips.indexOf(facts.getAttribute("data-ip")) === -1) ips.push(facts.getAttribute("data-ip"));
  if (!ips.length) return;
  function level(s) { return s >= 75 ? "s-bad" : (s >= 25 ? "s-warn" : "s-ok"); }
  function describe(d) {
    var parts = [];
    if (d.score !== undefined && d.score !== null) parts.push("AbuseIPDB abuse confidence " + d.score + "%");
    if (d.reports !== undefined && d.reports !== null) parts.push(d.reports + " report" + (d.reports === 1 ? "" : "s") + " in 90 days" + (d.users ? " by " + d.users + " user" + (d.users === 1 ? "" : "s") : ""));
    if (d.isp) parts.push(d.isp);
    if (d.usage) parts.push(d.usage);
    if (d.tor) parts.push("Tor exit node");
    if (d.whitelisted) parts.push("whitelisted by AbuseIPDB");
    return parts.join(" · ");
  }
  function fill(map) {
    tags.forEach(function (t) {
      var d = map[t.getAttribute("data-abuse-ip")];
      if (!d || d.private) { t.remove(); return; }
      if (d.error) { t.textContent = "?"; t.className = "score"; t.title = "AbuseIPDB: " + d.error; return; }
      if (d.score === undefined || d.score === null) { t.remove(); return; }
      t.textContent = d.score + "%";
      t.className = "score " + level(d.score);
      t.title = describe(d);
    });
    if (facts) {
      var d = map[facts.getAttribute("data-ip")] || {};
      var set = function (f, v) { var el = facts.querySelector('[data-f="' + f + '"]'); if (el) el.textContent = (v === undefined || v === null || v === "") ? "–" : v; };
      if (d.private) { set("score", "not checked (private address)"); ["reports", "isp", "usage", "domain", "last"].forEach(function (f) { set(f, "–"); }); }
      else if (d.error) { set("score", d.error); ["reports", "isp", "usage", "domain", "last"].forEach(function (f) { set(f, "–"); }); }
      else {
        var sc = facts.querySelector('[data-f="score"]');
        if (sc && d.score !== undefined && d.score !== null) { sc.innerHTML = ""; var s = document.createElement("span"); s.className = "score " + level(d.score); s.textContent = d.score + "%"; sc.appendChild(s); sc.appendChild(document.createTextNode(d.whitelisted ? " (whitelisted)" : (d.tor ? " (Tor exit node)" : ""))); }
        set("reports", d.reports !== undefined && d.reports !== null ? d.reports + (d.users ? " by " + d.users + " user" + (d.users === 1 ? "" : "s") : "") : null);
        set("isp", d.isp); set("usage", d.usage); set("domain", d.domain);
        set("last", d.last ? new Date(d.last).toLocaleString() : "never");
      }
    }
  }
  var map = {};
  var batches = [];
  for (var i = 0; i < ips.length; i += 25) batches.push(ips.slice(i, i + 25));
  batches.reduce(function (p, batch) {
    return p.then(function () {
      return fetch("/ipinfo?" + batch.map(function (ip) { return "ip=" + encodeURIComponent(ip); }).join("&"), { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (!j) return;
          if (!j.status.enabled) { tags.forEach(function (t) { t.remove(); }); tags = []; }
          Object.keys(j.ips || {}).forEach(function (k) { map[k] = j.ips[k]; });
          fill(map);
        });
    });
  }, Promise.resolve()).catch(function () { tags.forEach(function (t) { t.textContent = "?"; t.title = "AbuseIPDB score unavailable"; }); });
});

// ---- Reload / Restart: show that it's working right away, instead of a page that looks frozen ----
// (runs after the confirmation prompt; a cancelled prompt has already prevented the submit)
document.addEventListener("submit", function (e) {
  var f = e.target;
  if (e.defaultPrevented || !f.action) return;
  var path = new URL(f.action, location.href).pathname;
  var what = path === "/reload" ? ((f.querySelector('input[name="jail"]') || {}).value ? "Reloading jail " + f.querySelector('input[name="jail"]').value + "…" : "Reloading Fail2ban…")
           : path === "/restart" ? "Restarting the Fail2ban container…" : null;
  if (!what) return;
  f.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
  var holder = document.getElementById("toasts");
  if (!holder) return;
  var t = document.createElement("div");
  t.className = "flash wait";
  t.setAttribute("role", "status");
  t.textContent = what + " Bans are kept.";
  holder.insertBefore(t, holder.firstChild);
});

// ---- "Fail2ban is restarting" card: count the seconds live (the page itself may not refresh) ----
document.addEventListener("DOMContentLoaded", function () {
  var spans = document.querySelectorAll("[data-count-from]");
  if (!spans.length) return;
  var t0 = Date.now();
  setInterval(function () {
    spans.forEach(function (s) {
      s.textContent = (parseInt(s.getAttribute("data-count-from"), 10) || 0) + Math.floor((Date.now() - t0) / 1000);
    });
  }, 1000);
});
