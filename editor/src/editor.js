// Configuration editor for Fail2ban files: replaces <textarea data-editor> with CodeMirror 6.
// Bundled with esbuild into /static/editor.js during the Docker build. Without the bundle the page still
// works with the plain textarea.
import { EditorState, Compartment, RangeSetBuilder } from "@codemirror/state";
import {
  EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, highlightSpecialChars,
  drawSelection, rectangularSelection, crosshairCursor, hoverTooltip, ViewPlugin, Decoration
} from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import {
  StreamLanguage, indentUnit, foldGutter, foldKeymap, bracketMatching, syntaxHighlighting, HighlightStyle
} from "@codemirror/language";
import { python } from "@codemirror/lang-python";
import { tags as t } from "@lezer/highlight";
import { linter, lintGutter, openLintPanel, forEachDiagnostic, diagnosticCount, forceLinting } from "@codemirror/lint";
import { autocompletion, completionKeymap } from "@codemirror/autocomplete";
import { optionsFor, SECTIONS } from "./options.js";

// ---------- Fail2ban's INI dialect ----------
const ini = StreamLanguage.define({
  name: "fail2ban",
  startState: () => ({ afterKey: false, inValue: false }),
  token(stream, state) {
    if (stream.sol()) {
      state.afterKey = false;
      state.inValue = false;
      if (stream.match(/^[#;].*/)) return "comment";
      if (stream.match(/^\[[^\]]*\]/)) return "heading";
      if (/^\s/.test(stream.string)) {   // continuation of the previous value
        if (stream.match(/^\s+[#;].*/)) return "comment";
        state.inValue = true;
      } else if (stream.match(/^[^=:\s#;[][^=:]*?(?=\s*[=:])/)) {
        state.afterKey = true;
        return "propertyName";
      }
    }
    if (state.afterKey) {
      stream.eatSpace();
      if (stream.match(/^[=:]/)) { state.afterKey = false; state.inValue = true; return "operator"; }
    }
    if (stream.eatSpace()) return null;
    if (state.inValue) {
      if (stream.match(/^%\([^)]*\)s/)) return "variableName.special";
      if (stream.match(/^<[A-Za-z][\w\-.]*>/)) return "tagName";
      if (stream.match(/^"(?:[^"\\]|\\.)*"?/) || stream.match(/^'(?:[^'\\]|\\.)*'?/)) return "string";
      if (stream.match(/^-?\d+(?:\.\d+)?(?:[smhdwy]|mo)?(?![\w.])/)) return "number";
      if (stream.match(/^(?:true|false|yes|no)(?![\w.])/i)) return "bool";
      if (stream.match(/^[\w.-]+(?=\[)/)) return "keyword";   // action / filter name with arguments
      stream.next();
      return "content";
    }
    stream.skipToEnd();
    return null;
  },
  languageData: { commentTokens: { line: "#" } }
});

// ---------- parsing helpers ----------
const SECTION_RE = /^\[([^\]]*)\]/;
const KEY_RE = /^([^=:\s#;[][^=:]*?)\s*[=:]/;

// [{line, section, key, value(first line), from}] plus sections, for lint and completion
function scan(doc) {
  const out = { opts: [], sections: [] };
  let section = null, last = null;
  for (let i = 1; i <= doc.lines; i++) {
    const line = doc.line(i), text = line.text;
    if (!text.trim() || /^\s*[#;]/.test(text)) continue;
    let m;
    if ((m = SECTION_RE.exec(text))) {
      section = m[1].trim();
      out.sections.push({ line: i, name: section, from: line.from, to: line.to });
      last = null;
      continue;
    }
    if (/^\s/.test(text)) {   // continuation
      if (last) last.cont.push({ line: i, text: text.trim(), from: line.from });
      continue;
    }
    if ((m = KEY_RE.exec(text))) {
      last = { line: i, section, key: m[1].trim(), value: text.slice(m[0].length).trim(), from: line.from,
               to: line.to, cont: [] };
      out.opts.push(last);
    } else {
      out.opts.push({ line: i, section, bad: true, from: line.from, to: line.to, text });
      last = null;
    }
  }
  return out;
}

function sectionAt(doc, pos) {
  for (let i = doc.lineAt(pos).number; i >= 1; i--) {
    const m = SECTION_RE.exec(doc.line(i).text);
    if (m) return m[1].trim();
  }
  return null;
}

// the option a (possibly continued) line belongs to
function keyAt(doc, lineNo) {
  for (let i = lineNo; i >= 1; i--) {
    const text = doc.line(i).text;
    if (!text.trim() || /^\s*[#;]/.test(text)) continue;
    if (SECTION_RE.test(text)) return null;
    if (/^\s/.test(text)) continue;
    const m = KEY_RE.exec(text);
    return m ? m[1].trim() : null;
  }
  return null;
}

const names = (v) => v.split(/\n/).map((s) => s.trim()).filter((s) => s && !/^[#;]/.test(s) && !s.includes("%("))
  .map((s) => s.split(/[\s[]/)[0]).filter(Boolean);

// ---------- problems ----------
function localDiagnostics(state, data) {
  const doc = state.doc, out = [];
  const add = (from, to, severity, message, source = "Editor") =>
    out.push({ from, to: Math.max(to, from), severity, message, source });
  if (data.lang === "python") return out;
  const s = scan(doc);
  const seenSec = {};
  for (const sec of s.sections) {
    if (seenSec[sec.name]) add(sec.from, sec.to, "error", `Section [${sec.name}] already appears on line ${seenSec[sec.name]}. Fail2ban refuses duplicate sections in one file.`);
    else seenSec[sec.name] = sec.line;
  }
  const seenKey = {};
  const known = new Set([...(data.filters || [])]), acts = new Set([...(data.actions || [])]);
  const hasPref = s.opts.some((o) => o.key === "prefregex" && o.value);
  for (const o of s.opts) {
    if (o.bad) {
      add(o.from, o.to, "error", "Fail2ban can't read this line: it isn't 'name = value', a [section], a comment, or an indented continuation line.");
      continue;
    }
    if (o.section === null) {
      add(o.from, o.to, "error", "This option is outside any section. Add a [section] header above it (for a jail: [jailname]).");
      continue;
    }
    const id = o.section + "\0" + o.key.toLowerCase();
    if (seenKey[id]) add(o.from, o.to, "error", `'${o.key}' is already set in [${o.section}] on line ${seenKey[id]}. Fail2ban refuses this; for several values use indented continuation lines.`);
    else seenKey[id] = o.line;
    const full = [o.value, ...o.cont.map((c) => c.text)].join("\n");
    if (data.kind === "jail" || (data.kind === "main" && o.section !== "INCLUDES" && o.section !== "Definition")) {
      if (o.key === "enabled" && o.value && !/^(true|false|yes|no|1|0|on|off)$/i.test(o.value))
        add(o.from, o.to, "warning", "enabled should be true or false.");
      if (o.key === "filter" && known.size) {
        for (const n of names(full)) if (!known.has(n)) add(o.from, o.to, "warning", `There's no filter called '${n}' (neither in filter.d here nor among Fail2ban's stock filters).`);
      }
      if ((o.key === "action" || o.key === "banaction") && acts.size) {
        const lines = [{ text: o.value, from: o.from, to: o.to }, ...o.cont.map((c) => ({ text: c.text, from: c.from, to: c.from + c.text.length + 1 }))];
        for (const l of lines) {
          for (const n of names(l.text)) if (!acts.has(n)) add(l.from, l.to, "warning", `There's no action called '${n}' (neither in action.d here nor among Fail2ban's stock actions).`);
        }
      }
    }
    if (data.kind === "filter" && o.key === "failregex" && !hasPref) {
      const lines = [{ text: o.value, from: o.from, to: o.to }, ...o.cont.map((c) => ({ text: c.text, from: c.from, to: c.from + c.text.length + 1 }))];
      for (const l of lines) {
        if (l.text && !l.text.includes("%(") && !/<(HOST|ADDR|IP4|IP6|DNS|CIDR|SUBNET|F-ID|F-USER|F-[A-Z]+)>|\(\?P<(ip4|ip6|dns|cidr|fid|host)>/i.test(l.text))
          add(l.from, l.to, "error", "This regular expression has no <HOST> (or <ADDR>, <F-ID>) group, so Fail2ban can't tell which address to ban.");
      }
    }
  }
  return out;
}

// Messages from the server-side check ("Check only" / "Check & save"), placed on lines where possible
function serverDiagnostics(state, data, check) {
  const doc = state.doc, out = [];
  if (!check) return out;
  const s = data.lang === "python" ? { opts: [], sections: [] } : scan(doc);
  const lineDiag = (n, severity, message) => {
    if (n < 1 || n > doc.lines) return false;
    const l = doc.line(n);
    out.push({ from: l.from, to: l.to, severity, message, source: "Fail2ban check" });
    return true;
  };
  const items = [...(check.errors || []).map((m) => ["error", m]), ...(check.warnings || []).map((m) => ["warning", m])];
  for (const [sev, msg] of items) {
    let placed = false;
    const f = /'([^'\n]+\.(?:conf|local|py))'/.exec(msg);
    if (f && (f[1] === data.rel || f[1].endsWith("/" + data.rel))) {
      for (const m of msg.matchAll(/\[line\s+(\d+)\]/g)) placed = lineDiag(+m[1], sev, msg) || placed;
    }
    if (!placed && data.kind === "filter") {
      const m = /invalid (failregex|ignoreregex|prefregex|datepattern)/.exec(msg);
      if (m) for (const o of s.opts) if (o.key === m[1]) placed = lineDiag(o.line, sev, msg) || placed;
    }
    if (!placed && (data.kind === "jail" || data.kind === "main")) {
      const j = /[Jj]ail '([^']+)'/.exec(msg);
      if (j) {
        let target = null;
        if (/filter/i.test(msg)) target = s.opts.find((o) => o.section === j[1] && o.key === "filter");
        else if (/action/i.test(msg)) target = s.opts.find((o) => o.section === j[1] && o.key === "action");
        else if (/log file|logpath|glob/i.test(msg)) target = s.opts.find((o) => o.section === j[1] && o.key === "logpath");
        const sec = s.sections.find((x) => x.name === j[1]);
        if (target) placed = lineDiag(target.line, sev, msg);
        else if (sec) placed = lineDiag(sec.line, sev, msg);
      }
      const g = /No file\(s\) found for glob (\S+)/.exec(msg);
      if (!placed && g) {
        for (const o of s.opts) if (o.key === "logpath" && [o.value, ...o.cont.map((c) => c.text)].some((v) => v.split(/\s/)[0] === g[1])) placed = lineDiag(o.line, sev, msg);
      }
    }
  }
  return out;
}

// ---------- completion and hover docs ----------
function completions(data) {
  return (ctx) => {
    if (data.lang === "python") return null;
    const doc = ctx.state.doc, line = doc.lineAt(ctx.pos), before = line.text.slice(0, ctx.pos - line.from);
    const section = sectionAt(doc, ctx.pos);
    // [section]
    if (/^\[[\w.-]*$/.test(before)) {
      const word = ctx.matchBefore(/[\w.-]*/);
      return { from: word.from, options: (SECTIONS[data.kind] || []).map((s) => ({ label: s, apply: s + "]", type: "namespace" })) };
    }
    // option name at the start of a line
    if (/^[\w.]*$/.test(before)) {
      const word = ctx.matchBefore(/[\w.]*/);
      if (!word || (word.from === word.to && !ctx.explicit)) return null;
      const opts = optionsFor(data.kind, section);
      return {
        from: word.from, validFor: /^[\w.]*$/,
        options: Object.keys(opts).map((k) => ({ label: k, apply: k + " = ", type: "property", info: opts[k].doc }))
      };
    }
    // a value: after "key =" or on a continuation line
    let key = null, m;
    if ((m = /^([^=:\s#;[][^=:]*?)\s*[=:]\s*/.exec(before))) key = m[1].trim();
    else if (/^\s+/.test(before)) key = keyAt(doc, line.number - 1 >= 1 ? line.number : line.number);
    if (!key) return null;
    const spec = optionsFor(data.kind, section)[key];
    if (!spec || !spec.values) return null;
    const word = ctx.matchBefore(/[\w.%()-]*/);
    if (!word || (word.from === word.to && !ctx.explicit && !/[=:]\s*$/.test(before))) return null;
    let values = spec.values;
    if (values === "filters") values = data.filters || [];
    if (values === "actions") {
      values = [...(data.actions || [])];
      if (key === "action") values.unshift("%(action_)s", "%(action_mw)s", "%(action_mwl)s", "%(action_xarf)s");
    }
    return { from: word.from, options: values.map((v) => ({ label: v, type: "constant" })) };
  };
}

function hoverDocs(data) {
  return hoverTooltip((view, pos) => {
    if (data.lang === "python") return null;
    const line = view.state.doc.lineAt(pos);
    const m = KEY_RE.exec(line.text);
    if (!m) return null;
    const key = m[1].trim(), start = line.from, end = line.from + m[1].length;
    if (pos < start || pos > end) return null;
    const spec = optionsFor(data.kind, sectionAt(view.state.doc, pos))[key];
    if (!spec) return null;
    return {
      pos: start, end, above: true,
      create() {
        const dom = document.createElement("div");
        dom.className = "cm-f2b-info";
        const b = document.createElement("b"); b.textContent = key;
        const d = document.createElement("div"); d.textContent = spec.doc;
        dom.appendChild(b); dom.appendChild(d);
        if (Array.isArray(spec.values)) {
          const v = document.createElement("div"); v.className = "cm-f2b-meta"; v.textContent = "Values: " + spec.values.join(", ");
          dom.appendChild(v);
        }
        return { dom };
      }
    };
  });
}

// ---------- secrets: blurred on screen until the cursor is in them ----------
const SECRET_NAME = /(pass(word)?|secret|token|api_?key|apikey|(^|[_-])key)$/i;
const NOT_SECRET = /(public|_length|_size|_file|_path|keyfile)/i;
function secretRanges(doc) {
  const out = [];
  for (let i = 1; i <= doc.lines; i++) {
    const l = doc.line(i), text = l.text;
    if (/^\s*[#;]/.test(text)) continue;
    const m = KEY_RE.exec(text);
    if (m && SECRET_NAME.test(m[1].trim()) && !NOT_SECRET.test(m[1])) {
      const vstart = m[0].length + (/^\s*/.exec(text.slice(m[0].length))[0].length);
      if (vstart < text.length) out.push([l.from + vstart, l.to]);
      continue;
    }
    // arguments inside values: name[abuseipdb_apikey="...", cftoken=...]
    const re = /([\w-]+)\s*=\s*("[^"]*"|'[^']*'|[^,\]\s"']+)/g;
    let a;
    const offset = m ? m[0].length : 0;
    re.lastIndex = offset;
    while ((a = re.exec(text))) {
      if (SECRET_NAME.test(a[1]) && !NOT_SECRET.test(a[1])) {
        const vfrom = a.index + a[0].length - a[2].length;
        out.push([l.from + vfrom, l.from + a.index + a[0].length]);
      }
    }
  }
  return out;
}
const blur = Decoration.mark({ class: "cm-secret", attributes: { title: "Secret hidden on screen: click to show" } });
const hideSecrets = () => ViewPlugin.fromClass(class {
  constructor(view) { this.ranges = secretRanges(view.state.doc); this.decorations = this.build(view); }
  update(u) {
    if (u.docChanged) this.ranges = secretRanges(u.state.doc);
    if (u.docChanged || u.selectionSet) this.decorations = this.build(u.view);
  }
  build(view) {
    const b = new RangeSetBuilder();
    for (const [f, to] of this.ranges) {
      if (to <= f) continue;
      if (view.state.selection.ranges.some((r) => r.from <= to && r.to >= f)) continue;
      b.add(f, to, blur);
    }
    return b.finish();
  }
}, { decorations: (v) => v.decorations });

// ---------- look ----------
const theme = EditorView.theme({
  "&": { backgroundColor: "var(--bg)", color: "var(--fg)", border: "1px solid var(--bd)", borderRadius: "8px", fontSize: "13px" },
  "&.cm-focused": { outline: "2px solid var(--pri)", outlineOffset: "-1px" },
  ".cm-scroller": { fontFamily: "ui-monospace,'Cascadia Code',Consolas,monospace", lineHeight: "1.6" },
  ".cm-content": { caretColor: "var(--pri)", padding: ".5rem 0" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--pri)", borderLeftWidth: "2px" },
  ".cm-gutters": { backgroundColor: "var(--card)", color: "var(--mut)", borderRight: "1px solid var(--bd)", borderRadius: "8px 0 0 8px" },
  ".cm-activeLine": { backgroundColor: "color-mix(in srgb, var(--pri) 6%, transparent)" },
  ".cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--pri) 12%, transparent)", color: "var(--fg)" },
  "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, ::selection":
    { backgroundColor: "color-mix(in srgb, var(--pri) 26%, transparent) !important" },
  ".cm-selectionMatch": { backgroundColor: "color-mix(in srgb, var(--pri) 14%, transparent)" },
  ".cm-matchingBracket": { backgroundColor: "color-mix(in srgb, var(--ok) 25%, transparent)", outline: "none" },
  ".cm-foldPlaceholder": { backgroundColor: "var(--pri-soft)", color: "var(--pri-fg)", border: "none", padding: "0 .4rem" },
  ".cm-panels": { backgroundColor: "var(--card)", color: "var(--fg)" },
  ".cm-panels.cm-panels-top": { borderBottom: "1px solid var(--bd)" },
  ".cm-panels.cm-panels-bottom": { borderTop: "1px solid var(--bd)" },
  ".cm-textfield": { backgroundColor: "var(--bg)", color: "var(--fg)", border: "1px solid var(--bd)", borderRadius: "6px" },
  ".cm-button": { backgroundImage: "none", backgroundColor: "var(--bg)", color: "var(--fg)", border: "1px solid var(--bd)", borderRadius: "6px" },
  ".cm-searchMatch": { backgroundColor: "color-mix(in srgb, #f5b400 35%, transparent)" },
  ".cm-searchMatch.cm-searchMatch-selected": { backgroundColor: "color-mix(in srgb, #f5b400 65%, transparent)" },
  ".cm-tooltip": { backgroundColor: "var(--card)", color: "var(--fg)", border: "1px solid var(--bd)", borderRadius: "8px", boxShadow: "0 6px 18px rgba(0,0,0,.18)" },
  ".cm-tooltip-lint": { padding: "2px" },
  ".cm-diagnostic": { padding: ".35rem .6rem", maxWidth: "64ch", whiteSpace: "pre-wrap" },
  ".cm-diagnostic-error": { borderLeftColor: "var(--bad)" },
  ".cm-diagnostic-warning": { borderLeftColor: "var(--warn)" },
  ".cm-diagnosticSource": { color: "var(--mut)", fontSize: ".8em" },
  ".cm-lintRange-error": { backgroundColor: "color-mix(in srgb, var(--bad) 12%, transparent)" },
  ".cm-lintRange-warning": { backgroundColor: "color-mix(in srgb, var(--warn) 12%, transparent)" },
  ".cm-panel.cm-panel-lint ul [aria-selected]": { backgroundColor: "var(--pri-soft)", color: "var(--pri-fg)" },
  ".cm-tooltip-autocomplete > ul > li[aria-selected]": { backgroundColor: "var(--pri)", color: "var(--on-pri)" },
  ".cm-completionMatchedText": { textDecoration: "none", fontWeight: "700" },
  ".cm-tooltip.cm-completionInfo": { padding: ".5rem .7rem", maxWidth: "26rem" },
  ".cm-f2b-info": { padding: ".45rem .65rem", maxWidth: "28rem", fontFamily: "system-ui,sans-serif", fontSize: "13px", lineHeight: "1.45" },
  ".cm-f2b-info > div": { marginTop: ".25rem" },
  ".cm-f2b-meta": { color: "var(--mut)", fontSize: "12px" },
  ".cm-secret": { filter: "blur(4.5px)", cursor: "pointer" }
});

const highlight = HighlightStyle.define([
  { tag: t.heading, color: "var(--hl-sec)", fontWeight: "700" },
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "var(--hl-key)", fontWeight: "600" },
  { tag: [t.string, t.special(t.string)], color: "var(--hl-str)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--hl-num)" },
  { tag: [t.comment, t.lineComment, t.blockComment], color: "var(--mut)", fontStyle: "italic" },
  { tag: [t.tagName, t.special(t.variableName)], color: "var(--hl-kw)", fontWeight: "600" },
  { tag: [t.keyword, t.controlKeyword, t.definitionKeyword, t.moduleKeyword], color: "var(--hl-kw)" },
  { tag: [t.function(t.variableName), t.className], color: "var(--hl-key)" },
  { tag: [t.operator, t.punctuation, t.separator, t.squareBracket, t.brace], color: "var(--mut)" }
]);

// ---------- preferences ----------
const PREFS_KEY = "f2bEditorPrefs";
const DEFAULTS = { lineNumbers: true, wrap: false, secrets: true };
function loadPrefs() {
  try { return Object.assign({}, DEFAULTS, JSON.parse(localStorage.getItem(PREFS_KEY) || "{}")); }
  catch (e) { return Object.assign({}, DEFAULTS); }
}
function savePrefs(p) { try { localStorage.setItem(PREFS_KEY, JSON.stringify(p)); } catch (e) {} }

function el(tag, attrs, text) {
  const e = document.createElement(tag);
  for (const k in attrs || {}) e.setAttribute(k, attrs[k]);
  if (text != null) e.textContent = text;
  return e;
}

function setup(ta) {
  let data = {};
  try { data = JSON.parse((document.getElementById("ed-data") || {}).textContent || "{}"); } catch (e) {}
  let check = null;
  try { check = JSON.parse(ta.getAttribute("data-check") || "null"); } catch (e) {}
  const prefs = loadPrefs();
  const numbersC = new Compartment(), wrapC = new Compartment(), secretsC = new Compartment();
  const numbersExt = (on) => on ? [lineNumbers(), foldGutter(), highlightActiveLineGutter()] : [];

  const bar = el("div", { class: "ed-bar" });
  const problems = el("button", { type: "button", class: "ed-problems", hidden: "" });
  const modified = el("span", { class: "ed-modified", hidden: "", title: "The editor differs from the file on disk" }, "● Modified");
  const toggles = el("div", { class: "ed-toggles" });
  bar.append(problems, modified, toggles);
  const diskText = ta.hasAttribute("data-ondisk") ? ta.value : (ta.getAttribute("data-disk") ?? "");
  const isNew = !ta.hasAttribute("data-ondisk") && !ta.getAttribute("data-disk") && !ta.form.querySelector('input[name="from_backup"]');
  let leaving = false, jumped = false, draftTimer = null;

  const host = el("div", { class: "ed-host" });
  ta.parentNode.insertBefore(bar, ta);
  ta.parentNode.insertBefore(host, ta);
  ta.style.display = "none";

  const lang = data.lang === "python" ? python() : ini;
  const view = new EditorView({
    parent: host,
    state: EditorState.create({
      doc: ta.value,
      extensions: [
        numbersC.of(numbersExt(prefs.lineNumbers)),
        wrapC.of(prefs.wrap ? EditorView.lineWrapping : []),
        secretsC.of(prefs.secrets ? hideSecrets() : []),
        highlightSpecialChars(), history(), drawSelection(),
        EditorState.allowMultipleSelections.of(true),
        bracketMatching(), rectangularSelection(), crosshairCursor(),
        highlightActiveLine(), highlightSelectionMatches(),
        indentUnit.of(data.lang === "python" ? "    " : "        "), EditorState.tabSize.of(4),
        lang, syntaxHighlighting(highlight), theme,
        autocompletion({ override: [completions(data)], icons: false }),
        hoverDocs(data),
        keymap.of([...completionKeymap, ...defaultKeymap, ...historyKeymap, ...searchKeymap, ...foldKeymap, indentWithTab]),
        EditorView.contentAttributes.of({ spellcheck: "false", "aria-label": data.rel || "configuration file" }),
        lintGutter(),
        linter((v) => [...localDiagnostics(v.state, data), ...serverDiagnostics(v.state, data, check)], { delay: 350 }),
        EditorView.updateListener.of((u) => {
          updateProblems(u.state);
          if (!u.docChanged) return;
          check = null;   // the server's findings were for the previous text
          ta.value = u.state.doc.toString();
          modified.hidden = !isNew && ta.value === diskText;
          clearTimeout(draftTimer);
          draftTimer = setTimeout(syncDraft, 500);
        })
      ]
    })
  });

  function firstProblem(state) {
    let first = null;
    forEachDiagnostic(state, (d, from) => { if (first == null || from < first) first = from; });
    return first;
  }
  function updateProblems(state) {
    const n = diagnosticCount(state);
    let errors = 0;
    forEachDiagnostic(state, (d) => { if (d.severity === "error") errors++; });
    problems.hidden = n === 0;
    problems.className = "ed-problems" + (errors ? " err" : "");
    problems.textContent = (errors ? "✖ " : "⚠ ") + n + (n === 1 ? " problem" : " problems");
    if (n && !jumped && check) {
      jumped = true;
      const pos = firstProblem(state);
      if (pos != null) setTimeout(() => view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: "center" }) }), 0);
    }
  }
  problems.addEventListener("click", () => {
    const pos = firstProblem(view.state);
    if (pos != null) view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: "center" }) });
    openLintPanel(view);
  });

  function toggle(label, key, apply) {
    const id = "ed-" + key;
    const wrap = el("label", { class: "ed-toggle", for: id });
    const cb = el("input", { type: "checkbox", id });
    cb.checked = !!prefs[key];
    cb.addEventListener("change", () => { prefs[key] = cb.checked; savePrefs(prefs); view.dispatch({ effects: apply(cb.checked) }); });
    wrap.append(cb, document.createTextNode(" " + label));
    toggles.appendChild(wrap);
  }
  toggle("Line numbers", "lineNumbers", (on) => numbersC.reconfigure(numbersExt(on)));
  toggle("Wrap lines", "wrap", (on) => wrapC.reconfigure(on ? EditorView.lineWrapping : []));
  toggle("Hide secrets", "secrets", (on) => secretsC.reconfigure(on ? hideSecrets() : []));

  // ---- unsaved edits kept in this browser (per file) ----
  const DRAFT_KEY = "f2bDraft:" + (data.rel || location.search);
  const getDraft = () => { try { return JSON.parse(localStorage.getItem(DRAFT_KEY) || "null"); } catch (e) { return null; } };
  const dropDraft = () => { try { localStorage.removeItem(DRAFT_KEY); } catch (e) {} };
  const keepDraft = (text) => { try { localStorage.setItem(DRAFT_KEY, JSON.stringify({ text, ts: Date.now() })); } catch (e) {} };
  function syncDraft() {
    const text = view.state.doc.toString();
    if (text === diskText) dropDraft(); else keepDraft(text);
  }
  if (ta.hasAttribute("data-saved")) dropDraft();
  const draft = getDraft();
  if (draft && draft.text !== ta.value) {
    const note = el("div", { class: "ed-draft", role: "status" });
    note.appendChild(el("span", null, "You have unsaved edits of this file from " + new Date(draft.ts).toLocaleString() + "."));
    const restore = el("button", { type: "button", class: "btn" }, "Restore them");
    const discard = el("button", { type: "button", class: "btn sec" }, "Discard");
    restore.addEventListener("click", () => { view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: draft.text } }); note.remove(); view.focus(); });
    discard.addEventListener("click", () => { dropDraft(); note.remove(); });
    note.append(restore, discard);
    bar.parentNode.insertBefore(note, bar);
  } else if (draft && draft.text === diskText) dropDraft();

  // ---- notice changes made elsewhere while the page is open ----
  const baseInput = ta.form && ta.form.querySelector('input[name="base"]');
  const fpUrl = ta.getAttribute("data-fingerprint");
  if (baseInput && fpUrl && !document.querySelector(".conflict")) {
    const notice = el("div", { class: "ed-outside", role: "alert", hidden: "" });
    notice.appendChild(el("span", null, "This file was changed outside this page after you opened it. If you save, you'll be asked whether to overwrite that change."));
    const load = el("a", { class: "btn sec", href: location.pathname + location.search.replace(/[?&](saved|from_backup)=[^&]*/g, ""), "data-leave-ok": "" }, "Load the current file");
    notice.appendChild(load);
    bar.parentNode.insertBefore(notice, bar);
    let checking = false;
    const poll = () => {
      if (checking || document.hidden) return;
      checking = true;
      fetch(fpUrl, { credentials: "same-origin", cache: "no-store" })
        .then((r) => (r.ok ? r.json() : null))
        .then((j) => { if (j && j.fp) notice.hidden = j.fp === baseInput.value; })
        .catch(() => {})
        .finally(() => { checking = false; });
    };
    poll();
    setInterval(poll, 20000);
    document.addEventListener("visibilitychange", poll);
    window.addEventListener("focus", poll);
  }

  modified.hidden = !isNew && ta.value === diskText;
  window.addEventListener("beforeunload", (e) => {
    if (leaving || (!isNew && view.state.doc.toString() === diskText)) return;
    if (isNew && view.state.doc.toString() === ta.defaultValue) return;
    e.preventDefault();
    e.returnValue = "";
  });
  document.addEventListener("click", (e) => { if (e.target.closest("[data-leave-ok]")) leaving = true; });

  const saveBtn = ta.form && ta.form.querySelector('button[value="save"]');
  if (saveBtn) {
    saveBtn.title = "Ctrl+S";
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (ta.form.requestSubmit) ta.form.requestSubmit(saveBtn); else saveBtn.click();
      }
    });
  }
  if (ta.form) ta.form.addEventListener("submit", () => {
    leaving = true;
    ta.value = view.state.doc.toString();
    clearTimeout(draftTimer);
    syncDraft();
  });
  if (check) forceLinting(view);
}

function init() { document.querySelectorAll("textarea[data-editor]").forEach(setup); }
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
