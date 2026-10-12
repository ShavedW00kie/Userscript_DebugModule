/**
 * File: userscript-debugger-module.js
 * Version: 1.0.4
 * Advanced Modular Userscript Debugger with optional DOM Inspector
 * Author: ShavedW00kie (Torn: ThaWookie [2954173] )
 * Namespace: https://github.com/ShavedW00kie/
 * Target: Embedded inside a Torn.com userscript IIFE (desktop and TornPDA).
 * License: BSD-3-Clause
 *
 * Copyright (c) 2026 ShavedW00kie
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Integration inside the host userscript's IIFE, AFTER this function definition:
 *   const MyDebug = initializeModularDebugger(GM_info.script.name);
 *   MyDebug.log("Ready");
 *   bugButton.addEventListener("click", () => MyDebug.toggleView());
 *   copyButton.addEventListener("click", function () { void MyDebug.copy(this); });
 *   // Optional: MyDebug.inspect(), MyDebug.inspectElement(element),
 *   // MyDebug.watchElement(element), MyDebug.stopInspection(), MyDebug.destroy().
 *
 * This file is a source module, not an independently installable userscript.
 * The host userscript supplies its own ==UserScript== metadata and IIFE.
 */
function initializeModularDebugger(scriptNamespace) {
    "use strict";
    if (scriptNamespace === undefined) scriptNamespace = "App";

    const randomId = (() => {
        try {
            if (typeof crypto !== "undefined" && crypto.randomUUID) {
                return crypto.randomUUID().replace(/-/g, "");
            }
        } catch (_) { /* WebView fallback. */ }
        return Math.random().toString(36).slice(2) + Date.now().toString(36);
    })();
    const id = `tw-debug-${randomId}`;
    const LIMITS = Object.freeze({
        buffer: (10 * 1024 * 1024) - (900 * 1024),
        entry: 64 * 1024,
        renderEntries: 180,
        renderChars: 128 * 1024,
        report: 15000,
        html: 6000,
        parents: 6,
        children: 12,
        nodes: 65,
        mutations: 40
    });
    const state = {
        logs: [], head: 0, length: 0, destroyed: false, 
        frames: new Set(), statuses: new Map(), resizeObserver: null,
        root: null, logArea: null, inspector: null, inspectorText: null,
        style: null, statusBar: null, highlight: null,
        panelMode: "logs", selected: null, picking: false,
        watching: false, changeLog: [],
        observer: null, parentObserver: null, uiObserver: null,
        observedBody: null, renderPending: false,
        pendingMutations: 0, mutationLogPending: false,
        viewportListeners: false, highlightPending: false
    };
    const SENSITIVE = /(?:^key$|api[_-]?key|apikey|token|auth|authorization|cookie|secret|passwd|password|csrf|session|bearer|credential|client[_-]?secret|refresh[_-]?token|access[_-]?token)/i;
    const SAFE_ATTRIBUTES = new Set([
        "id", "class", "role", "type", "aria-expanded",
        "aria-hidden", "data-testid", "data-test", "data-role", "data-state"
    ]);

    /* ---------- Redacted, bounded logging ---------- */
    function redact(value) {
        return String(value)
            .replace(/\b(?:Authorization|Proxy-Authorization)\s*:\s*[^\r\n]+/gi, "Authorization: [REDACTED]")
            .replace(/\b[A-Za-z0-9]{16}\b/g, "[POSSIBLE KEY REDACTED]")
            // Bearer tokens and known secret-bearing URL parameters.
            .replace(/(\bBearer\s+)[A-Za-z0-9._~+/-]+/gi, "$1[REDACTED]")
            .replace(/([?&](?:key|api_key|token|access_token|refresh_token|secret|session|csrf)=)[^&#\s\"'<>}\]]+/gi, "$1[REDACTED]")
            // Quoted property values, including embedded spaces.
            .replace(/(["']?(?:api[_-]?key|apikey|token|authorization|cookie|password|passwd|secret|csrf|session|access[_-]?token|refresh[_-]?token)["']?\s*[:=]\s*)(["'])([^"']*)\2/gi,
                (_, prefix, quote) => `${prefix}${quote}[REDACTED]${quote}`)
            // Unquoted key=value patterns.
            .replace(/(["']?(?:api[_-]?key|apikey|token|authorization|cookie|password|passwd|secret|csrf|session|access[_-]?token|refresh[_-]?token)["']?\s*[:=]\s*)(?!["'])([^\s"',;}&\]]+)/gi,
                (_, prefix) => `${prefix}[REDACTED]`);
    }

    // Does not call getters or toJSON. Proxies can still execute traps; never
    // deliberately pass hostile proxies to an in-process diagnostic function.
    function safeSerialize(value) {
        let remaining = 240;
        const path = new WeakSet();
        function visit(item, depth) {
            if (--remaining < 0) return "[Traversal limit]";
            if (typeof item === "string") return redact(item.slice(0, 8192));
            if (item === null || typeof item === "boolean" || typeof item === "number") return item;
            if (typeof item === "undefined") return "[undefined]";
            if (typeof item === "bigint" || typeof item === "symbol") return String(item);
            if (typeof item === "function") return "[Function]";
            if (path.has(item)) return "[Circular]";
            if (depth >= 5) return "[Depth limit]";
            path.add(item);
            try {
                const result = Object.create(null);
                let count = 0;
                if (item instanceof Error) {
                    for (const key of ["name", "message", "stack"]) {
                        const descriptor = Object.getOwnPropertyDescriptor(item, key);
                        result[key] = descriptor && "value" in descriptor
                            ? visit(descriptor.value, depth + 1) : "[Unavailable/accessor]";
                    }
                }
                // for-in permits early exit without allocating Object.keys for
                // every property. Reflection itself is not a hard time limit.
                for (const key in item) {
                    if (!Object.prototype.hasOwnProperty.call(item, key)) continue;
                    if (++count > 40 || remaining <= 0) { result["[Truncated]"] = true; break; }
                    const descriptor = Object.getOwnPropertyDescriptor(item, key);
                    result[redact(key.slice(0, 160))] = SENSITIVE.test(key) ? "[REDACTED]"
                        : descriptor && "value" in descriptor ? visit(descriptor.value, depth + 1) : "[Accessor omitted]";
                }
                return result;
            } catch (_) { return "[Unserializable]"; }
            finally { path.delete(item); }
        }
        try {
            if (typeof value === "string") return redact(value.slice(0, LIMITS.entry));
            return JSON.stringify(visit(value, 0));
        } catch (_) { return "[Unserializable]"; }
    }
    function scheduleFrame(callback) {
        if (state.destroyed) return;
        if (typeof requestAnimationFrame !== "function") { callback(); return; }
        const handle = requestAnimationFrame(() => {
            state.frames.delete(handle);
            if (!state.destroyed) callback();
        });
        state.frames.add(handle);
    }
    function trim(text, max) {
        text = String(text);
        return text.length > max ? `${text.slice(0, Math.max(0, max - 17))}[TRUNCATED]` : text;
    }
    function log(message, level = "INFO") {
        if (state.destroyed) return;
        const label = typeof level === "string" && /^(INFO|WARN|ERROR|DEBUG)$/i.test(level) ? level.toUpperCase() : "INFO";
        const timestamp = new Date().toISOString();
        const entry = trim(`[${timestamp}] [${label}] ${safeSerialize(message)}`, LIMITS.entry);
        const size = entry.length + 1;
        while (state.head < state.logs.length && state.length + size > LIMITS.buffer) {
            state.length -= state.logs[state.head].length + 1;
            state.logs[state.head++] = null; // Release pruned strings immediately.
        }
        if (state.head > 2048) { state.logs = state.logs.slice(state.head); state.head = 0; }
        state.logs.push(entry);
        state.length += size;
        queueRender();
    }
    const info = message => log(message, "INFO");
    const warn = message => log(message, "WARN");
    const error = message => log(message, "ERROR");
    function clear() {
        state.logs.length = 0;
        state.head = 0;
        state.length = 0;
        renderLogs();
    }
    function queueRender() {
        if (!state.logArea || !state.root || state.root.hidden || state.panelMode !== "logs") return;
        if (state.renderPending) return;
        state.renderPending = true;
        scheduleFrame(() => { state.renderPending = false; renderLogs(); });
    }
    function renderLogs() {
        if (state.destroyed || !state.root || state.root.hidden || !state.logArea || !state.logArea.isConnected || state.panelMode !== "logs") return;
        const subset = [];
        let chars = 0;
        for (let i = state.logs.length - 1; i >= state.head && subset.length < LIMITS.renderEntries; i--) {
            if (chars + state.logs[i].length + 1 > LIMITS.renderChars) break;
            subset.unshift(state.logs[i]); chars += state.logs[i].length + 1;
        }
        const skipped = state.logs.length - state.head - subset.length;
        state.logArea.textContent = (skipped ? `[${skipped} earlier entries retained for copying]\n` : "") + subset.join("\n");
        state.logArea.scrollTop = state.logArea.scrollHeight;
    }

    /* ---------- Clipboard (Tampermonkey, TornPDA, browser) ---------- */
    function copyFallback(text) {
        if (!document.body) return false;
        const input = document.createElement("textarea");
        const previousFocus = document.activeElement;
        const selection = typeof window.getSelection === "function" ? window.getSelection() : null;
        const ranges = [];
        if (selection) for (let i = 0; i < selection.rangeCount; i++) ranges.push(selection.getRangeAt(i).cloneRange());
        let caret = null;
        try { if (previousFocus && typeof previousFocus.selectionStart === "number") caret = [previousFocus.selectionStart, previousFocus.selectionEnd, previousFocus.selectionDirection]; } catch (_) {}
        input.value = text;
        input.readOnly = true;
        input.style.cssText = "position:fixed;left:0;top:0;width:1px;height:1px;opacity:0;z-index:-1";
        try {
            document.body.appendChild(input);
            input.focus();
            input.select();
            input.setSelectionRange(0, text.length);
            return Boolean(document.execCommand("copy"));
        } catch (_) { return false; }
        finally {
            input.remove();
            try { if (previousFocus && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
                if (caret) previousFocus.setSelectionRange(...caret);
                if (selection) { selection.removeAllRanges(); ranges.forEach(range => selection.addRange(range)); } } catch (_) { /* Non-focusable element. */ }
        }
    }
    async function writeClipboard(text) {
        try {
            if (typeof GM_setClipboard === "function") {
                await Promise.resolve(GM_setClipboard(text, "text"));
                return true;
            }
            if (typeof GM !== "undefined" && typeof GM.setClipboard === "function") {
                await GM.setClipboard(text, "text");
                return true;
            }
        } catch (_) { /* Try browser APIs. */ }
        if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
            try { await navigator.clipboard.writeText(text); return true; }
            catch (_) { /* Restricted WebView. */ }
        }
        return copyFallback(text);
    }
    function showCopyResult(button, result) {
        if (state.destroyed || !button || !button.isConnected) return;
        let saved = state.statuses.get(button);
        if (saved) clearTimeout(saved.timer);
        else saved = { nodes: Array.from(button.childNodes), timer: null };
        button.textContent = result;
        // This timer is only UI feedback, never element discovery or polling.
        saved.timer = setTimeout(() => {
            button.replaceChildren(...saved.nodes);
            state.statuses.delete(button);
        }, 1300);
        state.statuses.set(button, saved);
    }
    async function copy(button = null) {
        if (state.destroyed) return false;
        const text = state.logs.slice(state.head).join("\n");
        if (!text) { showCopyResult(button, "Empty"); return false; }
        const success = await writeClipboard(text);
        showCopyResult(button, success ? "Copied!" : "Failed");
        if (!success) warn("Clipboard unavailable. Open debugger to select and copy manually.");
        return success;
    }

    /* ---------- Safe DOM descriptions ---------- */
    function isElement(node) { return Boolean(node && node.nodeType === 1 && node.tagName); }
    function tag(node) { return isElement(node) ? node.tagName.toLowerCase() : "(none)"; }
    function describe(node) {
        if (!isElement(node)) return "(none)";
        let text = tag(node);
        const nodeId = node.getAttribute("id");
        if (nodeId && !SENSITIVE.test(nodeId)) text += `#${trim(redact(nodeId), 50)}`;
        const classes = Array.from(node.classList || []).filter(name => !SENSITIVE.test(name)).slice(0, 3);
        if (classes.length) text += "." + classes.map(name => trim(redact(name), 48)).join(".");
        return trim(text, 180);
    }
    function selectorSegment(node) {
        if (!isElement(node)) return "";
        const nodeId = node.getAttribute("id");
        if (nodeId && /^[A-Za-z_][\w-]{0,60}$/.test(nodeId) && !SENSITIVE.test(nodeId)) {
            return `#${nodeId}`;
        }
        let part = tag(node);
        const classNames = Array.from(node.classList || [])
            .filter(name => /^[A-Za-z_][\w-]{0,45}$/.test(name) && !SENSITIVE.test(name))
            .slice(0, 2);
        part += classNames.map(name => `.${name}`).join("");
        if (node.parentElement) {
            const same = Array.from(node.parentElement.children).filter(sibling => sibling.tagName === node.tagName);
            if (same.length > 1) part += `:nth-of-type(${same.indexOf(node) + 1})`;
        }
        return part;
    }
    function makeSelector(element) {
        const segments = [];
        let current = element;
        for (let step = 0; step < LIMITS.parents && isElement(current); step++) {
            const segment = selectorSegment(current);
            segments.unshift(segment);
            if (segment.startsWith("#")) break;
            current = current.parentElement;
        }
        const selector = segments.join(" > ");
        if (selector.length > 500) return "(selector exceeds safe length)";
        if (redact(selector) !== selector) return "(selector omitted: possible credential)";
        return selector;
    }
    function safeAttributeText(element) {
        const result = [];
        if (!isElement(element)) return "";
        for (const attr of Array.from(element.attributes || [])) {
            if (!SAFE_ATTRIBUTES.has(attr.name) || SENSITIVE.test(attr.name)) continue;
            if (SENSITIVE.test(attr.value)) continue;
            result.push(`${attr.name}="${escapeHTML(trim(redact(attr.value), 90))}"`);
            if (result.length >= 8) break;
        }
        return result.length ? ` ${result.join(" ")}` : "";
    }
    function escapeHTML(value) {
        return String(value).replace(/[&<>"']/g, character => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        })[character]);
    }
    function structuralHTML(element) {
        let budget = LIMITS.nodes;
        const skip = /^(script|style|noscript|template|iframe|object|embed)$/i;
        function recurse(node, depth) {
            if (!isElement(node) || budget-- <= 0) return "";
            const name = tag(node);
            const open = `<${name}${safeAttributeText(node)}>`;
            if (skip.test(name)) return `${open}[contents omitted]</${name}>`;
            if (depth >= 2) return `${open}[descendants omitted]</${name}>`;
            const kids = Array.from(node.children).slice(0, LIMITS.children);
            const nested = kids.map(child => recurse(child, depth + 1)).join("\n");
            const note = node.children.length > LIMITS.children ? "\n[additional children omitted]" : "";
            return `${open}${nested ? `\n${nested}${note}\n` : "[text omitted]"}</${name}>`;
        }
        return trim(recurse(element, 0), LIMITS.html);
    }
    function reactRootHint(element) {
        let node = element;
        for (let i = 0; i < LIMITS.parents && isElement(node); i++, node = node.parentElement) {
            const candidateId = node.getAttribute("id") || "";
            if (/^(?:react-root|root|__next)$/i.test(candidateId) || node.hasAttribute("data-reactroot")) {
                return `${describe(node)} (heuristic only)`;
            }
        }
        return "Not detected (does not rule out React)";
    }
    function getInspectionReport() {
        const element = state.selected;
        if (!isElement(element)) return "No element selected.";
        const ancestors = [];
        let ancestor = element.parentElement;
        for (let i = 0; i < LIMITS.parents && isElement(ancestor); i++, ancestor = ancestor.parentElement) {
            ancestors.push(`  ${i + 1}. ${describe(ancestor)}`);
        }
        const children = Array.from(element.children).slice(0, LIMITS.children)
            .map((child, index) => `  ${index + 1}. ${describe(child)}`);
        const page = typeof location !== "undefined"
            ? (location.origin === "null" ? "(local document)" : `${location.origin}${location.pathname}`)
            : "(unknown)";
        return trim(redact([
            `DOM INSPECTION | ${redact(String(scriptNamespace))}`,
            `Time: ${new Date().toISOString()}`,
            `Page (query omitted): ${redact(page)}`,
            `Selected: ${describe(element)}`,
            `Connected: ${element.isConnected}`,
            `Selector (best effort): ${makeSelector(element)}`,
            `React container hint: ${reactRootHint(element)}`,
            `Parent chain:\n${ancestors.join("\n") || "  (none)"}`,
            `Immediate children (${element.children.length}):\n${children.join("\n") || "  (none)"}`,
            `Sibling context: previous=${describe(element.previousElementSibling)}, next=${describe(element.nextElementSibling)}`,
            `Structural preview (text nodes, form values, URLs and scripts omitted; review attributes before sharing):\n${structuralHTML(element)}`,
            `Recent observed mutations (${state.changeLog.length}):\n${state.changeLog.join("\n") || "  (none)"}`
        ].join("\n\n")), LIMITS.report);
    }

    /* ---------- On-demand DOM selection and mutation watch ---------- */
    function isOurUI(node) {
        return Boolean(isElement(node) && (
            (state.root && state.root.contains(node)) ||
            (state.highlight && state.highlight.contains(node))
        ));
    }
    function ensureHighlight() {
        if (state.destroyed || !state.selected || !state.root || state.root.hidden || state.panelMode !== "inspect") return null;
        if (state.highlight && state.highlight.isConnected) return state.highlight;
        if (!document.body) return null;
        const node = document.createElement("div");
        node.setAttribute("aria-hidden", "true");
        node.style.cssText = "position:fixed;pointer-events:none;z-index:2147483646;border:2px solid #00dbff;box-shadow:0 0 0 1px #001e28;box-sizing:border-box;display:none";
        document.body.appendChild(node);
        state.highlight = node;
        return node;
    }
    function updateHighlight() {
        const marker = ensureHighlight();
        if (!marker) return;
        const node = state.selected;
        if (!isElement(node) || !node.isConnected || !state.root || state.root.hidden || state.panelMode !== "inspect") {
            marker.style.display = "none";
            return;
        }
        const rect = node.getBoundingClientRect();
        marker.style.display = "block";
        marker.style.top = `${rect.top}px`;
        marker.style.left = `${rect.left}px`;
        marker.style.width = `${rect.width}px`;
        marker.style.height = `${rect.height}px`;
    }
    function onViewportChanged() {
        if (state.destroyed || !state.selected || state.highlightPending || state.panelMode !== "inspect") return;
        state.highlightPending = true;
        scheduleFrame(() => {
            state.highlightPending = false;
            updateHighlight();
        });
    }
    function setViewportListeners(enable) {
        if (typeof window === "undefined" || enable === state.viewportListeners) return;
        state.viewportListeners = enable;
        const method = enable ? "addEventListener" : "removeEventListener";
        window[method]("scroll", onViewportChanged, true);
        window[method]("resize", onViewportChanged);
    }
    function removeHighlight() {
        if (state.highlight) { state.highlight.remove(); state.highlight = null; }
    }
    function updateInspector() {
        if (!state.inspectorText) return;
        state.inspectorText.textContent = state.selected ? trim([
            `Selected: ${describe(state.selected)}`,
            `Parent: ${describe(state.selected.parentElement)}`,
            `Children: ${state.selected.children.length}`,
            `Selector: ${makeSelector(state.selected)}`,
            `Connected: ${state.selected.isConnected}`,
            `Watch: ${state.watching ? "ON" : "OFF"} | Changes: ${state.changeLog.length}`
        ].join("\n"), 1100) : "Tap Pick, then tap a Torn page element.\nNo page data is collected until inspection is used.";
        if (state.statusBar) state.statusBar.textContent = state.picking ? "PICK MODE: tap a page element or press Esc" : "Inspector idle";
        updateHighlight();
    }
    function suppressPickAction(event) {
        if (isOurUI(event.target)) return;
        event.stopImmediatePropagation();
        // Preserve the browser synthetic click needed for tap selection.
    }
    function onPickClick(event) {
        if (isOurUI(event.target)) return;
        // Capture before Torn/React click handlers so selecting a link does not navigate.
        event.preventDefault();
        event.stopImmediatePropagation();
        if (isElement(event.target)) inspectElement(event.target);
        stopPicker();
    }
    function onPickKey(event) {
        if (event.key === "Escape") {
            event.preventDefault();
            stopPicker();
            updateInspector();
        }
    }
    function startPicker() {
        if (state.destroyed || !state.root || !state.root.isConnected || state.root.hidden || state.picking) return;
        state.picking = true;
        document.addEventListener("click", onPickClick, true);
        ["pointerdown", "pointerup", "touchstart", "touchend", "mousedown", "mouseup"].forEach(type => document.addEventListener(type, suppressPickAction, { capture: true, passive: false }));
        document.addEventListener("keydown", onPickKey, true);
        updateInspector();
    }
    function stopPicker() {
        if (!state.picking) return;
        state.picking = false;
        document.removeEventListener("click", onPickClick, true);
        ["pointerdown", "pointerup", "touchstart", "touchend", "mousedown", "mouseup"].forEach(type => document.removeEventListener(type, suppressPickAction, true));
        document.removeEventListener("keydown", onPickKey, true);
        updateInspector();
    }
    function stopWatch() {
        if (state.observer) state.observer.disconnect();
        if (state.parentObserver) state.parentObserver.disconnect();
        state.observer = null;
        state.parentObserver = null;
        state.watching = false;
        state.pendingMutations = 0;
        updateInspector();
    }
    function handleMutations(mutations) {
        if (!state.watching) return;
        const stamp = new Date().toISOString();
        let changed = 0;
        for (const mutation of mutations) {
            if (changed >= 8) break;
            const detail = mutation.type === "characterData" ? "text node changed (content omitted)" : mutation.type === "attributes"
                ? `attribute ${mutation.attributeName} on ${describe(mutation.target)}`
                : `childList (+${mutation.addedNodes.length}/-${mutation.removedNodes.length}) on ${describe(mutation.target)}`;
            state.changeLog.push(`[${stamp}] ${detail}`);
            changed++;
        }
        while (state.changeLog.length > LIMITS.mutations) state.changeLog.shift();
        if (changed) {
            state.pendingMutations += changed;
            if (!state.mutationLogPending) {
                state.mutationLogPending = true;
                scheduleFrame(() => {
                    state.mutationLogPending = false;
                    const count = state.pendingMutations;
                    state.pendingMutations = 0;
                    if (count && state.watching) log(`DOM watch: ${count} sampled change(s) near ${describe(state.selected)}`, "DEBUG");
                });
            }
        }
        if (state.selected && !state.selected.isConnected) {
            warn(`DOM watch: selected element detached: ${describe(state.selected)}`);
            stopWatch();
        }
        updateInspector();
    }
    function watchElement(element = state.selected) {
        if (state.destroyed || !isElement(element) || !element.isConnected || element === document.documentElement || element === document.body) {
            warn("DOM watch requires a specific element, not the document root/body.");
            return false;
        }
        if (typeof MutationObserver === "undefined") {
            warn("MutationObserver is unavailable in this WebView.");
            return false;
        }
        stopWatch();
        if (element !== state.selected && !inspectElement(element)) return false;
        state.changeLog.length = 0;
        // Observe the chosen subtree and direct child lists along its ancestor chain.
        state.observer = new MutationObserver(handleMutations);
        state.observer.observe(element, {
            attributes: true, childList: true, characterData: true, subtree: true,
            attributeFilter: ["class", "id", "role", "aria-expanded", "hidden", "disabled", "data-state"]
        });
        if (element.parentElement) {
            state.parentObserver = new MutationObserver(handleMutations);
            let ancestor = element.parentElement;
            while (ancestor) {
                state.parentObserver.observe(ancestor, { childList: true });
                ancestor = ancestor.parentNode;
            }
        }
        state.watching = true;
        info(`DOM watch enabled: ${describe(element)}`);
        updateInspector();
        return true;
    }
    function moveSelection(direction) {
        const selected = state.selected;
        if (!isElement(selected)) return;
        const next = direction === "parent" ? selected.parentElement : selected.firstElementChild;
        if (next && next !== document.body && next !== document.documentElement) inspectElement(next);
    }
    function inspectElement(element) {
        if (state.destroyed || !isElement(element) || isOurUI(element) || !ensureUI()) return false;
        if (state.watching && state.selected !== element) stopWatch();
        state.selected = element;
        if (state.resizeObserver) state.resizeObserver.disconnect();
        if (typeof ResizeObserver === "function") {
            state.resizeObserver = new ResizeObserver(onViewportChanged);
            state.resizeObserver.observe(element);
        }
        state.changeLog.length = 0;
        showPanel("inspect");
        updateInspector();
        info(`DOM selected: ${describe(element)} | ${makeSelector(element)}`);
        return true;
    }
    function inspect() {
        if (!showPanel("inspect")) return false;
        startPicker();
        return true;
    }
    function stopInspection() {
        stopPicker();
        stopWatch();
        state.selected = null;
        if (state.resizeObserver) state.resizeObserver.disconnect();
        state.resizeObserver = null;
        state.changeLog.length = 0;
        removeHighlight();
        setViewportListeners(false);
        if (state.root && !state.root.hidden) showPanel("logs");
    }
    async function copyInspection(button = null) {
        if (state.destroyed) return false;
        if (!state.selected) { showCopyResult(button, "No selection"); return false; }
        const result = await writeClipboard(getInspectionReport());
        showCopyResult(button, result ? "Copied!" : "Failed");
        return result;
    }

    /* ---------- Compact UI, created on first use ---------- */
    function createButton(text, label, handler) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = text;
        button.title = label;
        button.setAttribute("aria-label", label);
        button.className = `${id}-btn`;
        button.addEventListener("click", handler);
        return button;
    }
    function ensureStyles() {
        if (state.destroyed) return;
        if (state.style && state.style.isConnected) return;
        if (!document.head && !document.body) return;
        const style = document.createElement("style");
        style.id = `${id}-styles`;
        style.textContent = `
          @keyframes ${id}-reset {from{opacity:.7}to{opacity:1}}
          .${id}-flash{animation:${id}-reset 1.3s ease 1}
          #${id}{position:fixed;right:12px;bottom:12px;width:min(430px,calc(100vw - 24px));
            height:320px;max-height:70vh;display:flex;flex-direction:column;gap:8px;padding:10px;
            background:#191919;color:#e2ffe7;border:1px solid #46db85;border-radius:8px;
            box-shadow:0 6px 25px #0009;box-sizing:border-box;font:12px/1.45 monospace;
            z-index:2147483647;touch-action:manipulation}
          #${id}[hidden],#${id} [hidden]{display:none!important}
          #${id} button{font:11px/1.2 sans-serif;min-height:30px;cursor:pointer}
          #${id} .${id}-btn{border:1px solid #616161;border-radius:4px;background:#292929;
            color:#fff;padding:6px;touch-action:manipulation}
          #${id} .${id}-toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:4px}
          #${id} .${id}-title{font-weight:bold;flex:1 1 120px;min-width:0;overflow:hidden;text-overflow:ellipsis}
          #${id} .${id}-body{flex:1;min-height:0;overflow:auto;white-space:pre-wrap;
            overflow-wrap:anywhere;user-select:text}
          #${id} .${id}-actions{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:5px}
          #${id} .${id}-status{font-size:11px;color:#ace3fc}
          #${id} button:focus-visible{outline:2px solid #91dfff;outline-offset:2px}
          @media(max-width:480px){#${id}{right:8px;bottom:8px;width:calc(100vw - 16px);
            height:290px;font-size:11px}}
          @media(prefers-reduced-motion:reduce){.${id}-flash{animation:none}}
        `;
        (document.head || document.body).appendChild(style);
        state.style = style;
    }
    function ensureUI() {
        if (state.destroyed) return false;
        if (state.root && state.root.isConnected) { ensureStyles(); return true; }
        if (!document.body) return false;
        ensureStyles();
        const root = document.createElement("section");
        root.id = id;
        root.hidden = true;
        root.setAttribute("aria-label", `Debug console: ${String(scriptNamespace)}`);
        const toolbar = document.createElement("div");
        toolbar.className = `${id}-toolbar`;
        const title = document.createElement("span");
        title.className = `${id}-title`;
        title.textContent = `🪲 ${String(scriptNamespace)}`;
        toolbar.append(title,
            createButton("Copy", "Copy logs", function () { void copy(this); }),
            createButton("Clear", "Clear logs", clear),
            createButton("🔍", "Inspect Torn DOM element", inspect),
            createButton("Hide", "Hide debugger", () => toggleView()));
        const logArea = document.createElement("pre");
        logArea.className = `${id}-body`;
        logArea.style.margin = "0";
        const inspector = document.createElement("div");
        inspector.className = `${id}-body`;
        inspector.hidden = true;
        const actions = document.createElement("div");
        actions.className = `${id}-actions`;
        actions.append(
            createButton("Pick", "Pick element by tapping it", startPicker),
            createButton("↑ Parent", "Inspect parent element", () => moveSelection("parent")),
            createButton("↓ Child", "Inspect first child element", () => moveSelection("child")),
            createButton("Watch", "Watch selected element for DOM mutations", () => { watchElement(); }),
            createButton("Stop watch", "Disconnect mutation observers", stopWatch),
            createButton("Copy DOM", "Copy sanitized DOM report", function () { void copyInspection(this); }),
            createButton("Exit", "Close inspector", stopInspection));
        const status = document.createElement("div");
        status.className = `${id}-status`;
        const details = document.createElement("pre");
        details.style.cssText = "white-space:pre-wrap;overflow-wrap:anywhere;margin:5px 0;font:inherit";
        inspector.append(actions, status, details);
        root.append(toolbar, logArea, inspector);
        document.body.appendChild(root);
        Object.assign(state, { root, logArea, inspector, inspectorText: details, statusBar: status });
        attachUIObserver();
        return true;
    }
    function attachUIObserver() {
        if (typeof MutationObserver === "undefined" || !document.body) return;
        if (state.uiObserver) state.uiObserver.disconnect();
        // Only direct children of body, not the constantly changing React subtree.
        state.uiObserver = new MutationObserver(() => {
            if (state.root && (!state.root.isConnected || state.observedBody !== document.body)) {
                stopPicker();
                stopWatch();
                removeHighlight();
                setViewportListeners(false);
                if (state.root) state.root.remove();
                if (state.resizeObserver) state.resizeObserver.disconnect();
                state.resizeObserver = null;
                state.selected = null;
                state.root = state.logArea = state.inspector = state.inspectorText = state.statusBar = null;
                state.uiObserver.disconnect();
            }
        });
        state.uiObserver.observe(document.body, { childList: true });
        if (document.documentElement) state.uiObserver.observe(document.documentElement, { childList: true });
        state.observedBody = document.body;
    }
    function showPanel(panel) {
        if (!ensureUI()) return false;
        state.root.hidden = false;
        state.panelMode = panel;
        setViewportListeners(panel === "inspect");
        state.logArea.hidden = panel !== "logs";
        state.inspector.hidden = panel !== "inspect";
        if (panel === "logs") renderLogs();
        else updateInspector();
        return true;
    }
    function toggleView() {
        if (!ensureUI()) return false;
        if (!state.root.hidden) {
            // A hidden debugger must not keep an active DOM picker or watch.
            stopInspection();
            state.root.hidden = true;
            return false;
        }
        showPanel("logs");
        return true;
    }

    function destroy() {
        if (state.destroyed) return;
        state.destroyed = true;
        stopInspection();
        if (state.uiObserver) state.uiObserver.disconnect();
        if (state.resizeObserver) state.resizeObserver.disconnect();
        for (const handle of state.frames) {
            if (typeof cancelAnimationFrame === "function") cancelAnimationFrame(handle);
        }
        state.frames.clear();
        for (const [button, saved] of state.statuses) {
            clearTimeout(saved.timer);
            button.replaceChildren(...saved.nodes);
        }
        state.statuses.clear();
        if (state.root) state.root.remove();
        if (state.style) state.style.remove();
        removeHighlight();
        state.root = state.logArea = state.inspector = state.inspectorText = state.statusBar = state.style = null;
        clear();
    }

    return Object.freeze({
        log, info, warn, error, copy, clear, toggleView,
        inspect, inspectElement, watchElement, stopInspection,
        getInspectionReport, copyInspection, destroy
    });
}
