// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/** The only stylesheet of the web UI, served from /static/app.css (CSP: style-src 'self'). */
export const APP_CSS = `
:root{color-scheme:light dark;--bg:#fbfbfa;--panel:#fff;--fg:#1b1b1b;--muted:#5b5b5b;--line:#d9d9d6;--accent:#0b5cad;--accent-fg:#fff;--bad:#a4161a;--bad-bg:#fde8e8;--warn:#7a4b00;--warn-bg:#fff3d6;--ok:#1d6b2f;--ok-bg:#e5f4e8;--focus:#0b5cad}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--panel:#1b1b1b;--fg:#ececec;--muted:#b3b3b3;--line:#363636;--accent:#7ab7ff;--accent-fg:#0d0d0d;--bad:#ff8a8a;--bad-bg:#3a1414;--warn:#ffd27a;--warn-bg:#3a2c0b;--ok:#8fdc9f;--ok-bg:#12301a;--focus:#7ab7ff}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}
a:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid var(--focus);outline-offset:2px}
.skip{position:absolute;left:-9999px}.skip:focus{left:1rem;top:1rem;background:var(--panel);padding:.5rem;z-index:2}
header.top{border-bottom:1px solid var(--line);background:var(--panel)}
header.top .in,main,footer .in{max-width:64rem;margin:0 auto;padding:0 16px}
header.top .in{display:flex;flex-wrap:wrap;gap:.75rem 1.5rem;align-items:center;min-height:3.25rem}
header.top .brand{font-weight:700;text-decoration:none;color:var(--fg)}
nav ul{display:flex;flex-wrap:wrap;gap:1rem;list-style:none;margin:0;padding:0}
main{padding-top:1.5rem;padding-bottom:3rem}
h1{font-size:1.5rem;line-height:1.25;margin:0 0 1rem;overflow-wrap:anywhere}
h2{font-size:1.15rem;margin:2rem 0 .75rem}
h3{font-size:1rem;margin:1.25rem 0 .5rem}
.muted{color:var(--muted)}
.nowrap{white-space:nowrap}
.lock{margin-left:auto}
.q.open{border-left:3px solid var(--warn);padding-left:.75rem}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;background:var(--panel)}
table{border-collapse:collapse;width:100%;min-width:36rem}
th,td{text-align:left;padding:.5rem .75rem;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
th{font-size:.85rem;color:var(--muted);font-weight:600}
.badge{display:inline-block;padding:.05rem .45rem;border-radius:4px;font-size:.85rem;font-weight:600;white-space:nowrap}
.bad{background:var(--bad-bg);color:var(--bad)}
.warn{background:var(--warn-bg);color:var(--warn)}
.ok{background:var(--ok-bg);color:var(--ok)}
.flash{padding:.75rem 1rem;border-radius:6px;margin:0 0 1rem}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:1rem;margin:0 0 1rem}
dl.facts{display:grid;grid-template-columns:minmax(9rem,max-content) 1fr;gap:.35rem 1rem;margin:0}
dl.facts dt{color:var(--muted)}
dl.facts dd{margin:0;overflow-wrap:anywhere;white-space:pre-wrap}
form.stack{display:grid;gap:.9rem;max-width:44rem}
label{font-weight:600;display:block;margin-bottom:.25rem}
.hint{font-weight:400;color:var(--muted);font-size:.9rem;display:block}
input[type=text],input[type=datetime-local],textarea,select{width:100%;padding:.5rem .6rem;border:1px solid var(--line);border-radius:5px;background:var(--bg);color:var(--fg);font:inherit}
textarea{min-height:6rem;resize:vertical}
fieldset{border:1px solid var(--line);border-radius:6px;padding:.75rem 1rem;margin:0}
legend{font-weight:600;padding:0 .25rem}
.choices{display:flex;flex-wrap:wrap;gap:.35rem 1.25rem}
.choices label{font-weight:400;display:inline-flex;gap:.4rem;align-items:center;margin:0}
button{font:inherit;font-weight:600;padding:.5rem 1rem;border-radius:5px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);cursor:pointer}
button.secondary{background:transparent;color:var(--accent)}
.row{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center}
.q{border-top:1px solid var(--line);padding-top:.75rem}
.q:first-child{border-top:0;padding-top:0}
.ref{font-size:.85rem;color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;overflow-wrap:anywhere}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:.9rem;padding:1rem 0 2rem}
form.stack+form.stack{margin-top:1.75rem}
@media (max-width:40rem){dl.facts{grid-template-columns:1fr}dl.facts dt{margin-top:.5rem}
.table-wrap{overflow-x:visible}table{min-width:0}thead{position:absolute;left:-9999px}
table,tbody,tr,td{display:block}tr{border-bottom:1px solid var(--line);padding:.35rem 0}tr:last-child{border-bottom:0}
td{border:0;padding:.2rem .75rem;display:grid;grid-template-columns:6.5rem 1fr;gap:.5rem}
td::before{content:attr(data-label);color:var(--muted);font-size:.85rem;font-weight:600}}
`.trim();
