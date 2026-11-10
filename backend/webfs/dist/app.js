/* SSLVPN-Go 管理前端 v2 —— 对齐原版交互（无框架 SPA） */
"use strict";
const $app = document.getElementById("app");
/* 后端接口统一前缀（与后端 handler.APIPrefix 保持一致；改这里即可整体迁移） */
const API_BASE = "/api/v1";
let token = localStorage.getItem("sslvpn_token") || "";
let sysInfo = null; // 系统信息缓存（欢迎横幅用）

/* 品牌信息（名称/Logo/版权可由「全局设置」自定义，登录页与内部界面共用） */
const BRAND = { name: "KSVPN", logo_url: "/logo.png", custom_logo: false, copyright: "", copyright_url: "" };
async function loadBrand() {
  try {
    const d = await api("/system/getBrand");
    if (d.code === 1 && d.data) {
      BRAND.name = d.data.name || BRAND.name;
      BRAND.logo_url = d.data.logo_url || "/logo.png";
      BRAND.custom_logo = !!d.data.custom_logo;
      BRAND.copyright = d.data.copyright || "";
      BRAND.copyright_url = d.data.copyright_url || "";
    }
  } catch (e) { /* 品牌接口失败时用默认值 */ }
  document.title = BRAND.name + " 管理系统";
  const icon = document.querySelector('link[rel="icon"]');
  if (icon) icon.href = BRAND.custom_logo ? BRAND.logo_url : "/favicon.png";
}
function brandHTML(imgH) {
  return `<span class="brand-logo"><img src="${esc(BRAND.logo_url)}" alt="${esc(BRAND.name)}" style="height:${imgH}px"></span>`;
}

/* 底部版权栏：文字可配置；填写链接后文字带下划线并可点击跳转 */
function footerHTML() {
  const t = BRAND.copyright || "© 2026-至今 Power by KingStronger";
  const u = (BRAND.copyright_url || "").trim();
  const inner = (u && /^https?:\/\//i.test(u))
    ? `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(t)}</a>`
    : esc(t);
  return `<div class="page-footer">${inner}</div>`;
}
function loginFooterHTML() {
  const t = BRAND.copyright || "© 2026-至今 Power by KingStronger";
  const u = (BRAND.copyright_url || "").trim();
  const inner = (u && /^https?:\/\//i.test(u))
    ? `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(t)}</a>`
    : esc(t);
  return `<div class="login-footer">${inner}</div>`;
}
function refreshFooter() {
  const f = document.querySelector(".page-footer");
  if (f) f.outerHTML = footerHTML();
}

/* ================= 主题皮肤 ================= */
const THEMES = [
  { key: "teal",     name: "深青",  desc: "默认 · 沉稳内敛", primary: "#0f766e", lite: "#12a594", nav: "#101d26" },
  { key: "indigo",   name: "靛蓝",  desc: "现代 · 科技感",   primary: "#4338ca", lite: "#6366f1", nav: "#151a2e" },
  { key: "ocean",    name: "深海蓝", desc: "经典 · 企业蓝",   primary: "#1d4ed8", lite: "#3b82f6", nav: "#0d1a2f" },
  { key: "sky",      name: "淡蓝",  desc: "清爽 · 天青色",   primary: "#0284c7", lite: "#38bdf8", nav: "#0c2135" },
  { key: "graphite", name: "石墨灰", desc: "中性 · 极简",     primary: "#334155", lite: "#475569", nav: "#0f172a" },
  { key: "clay",     name: "赤陶",  desc: "暖调 · 差异化",   primary: "#a5471f", lite: "#c96a35", nav: "#231913" },
  { key: "light",    name: "浅色",  desc: "浅色侧栏 · 经典后台", primary: "#0f766e", lite: "#12a594", nav: "#f5f7f9" },
];
function currentTheme() {
  const k = localStorage.getItem("sslvpn_theme") || "teal";
  return THEMES.some(t => t.key === k) ? k : "teal";
}
function applyTheme(key) {
  const k = THEMES.some(t => t.key === key) ? key : "teal";
  document.body.setAttribute("data-theme", k);
  localStorage.setItem("sslvpn_theme", k);
  return k;
}
function themeModal() {
  const cur = currentTheme();
  formModal("主题皮肤", `
    <div class="tip-banner">ⓘ 切换只影响界面配色与侧栏样式，不影响任何功能、数据与权限。偏好保存在本机浏览器，换设备需重新选择。</div>
    <div class="theme-grid">
      ${THEMES.map(t => `<div class="theme-item ${t.key === cur ? "on" : ""}" data-theme-key="${t.key}">
        <div class="tname"><span>${t.name}</span><span class="tdot">
          <i style="background:${t.nav}"></i><i style="background:${t.primary}"></i><i style="background:${t.lite}"></i>
        </span></div>
        <div class="tprev"><span style="background:${t.nav}"></span><span><em style="background:${t.primary}"></em></span></div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
          <span class="muted" style="font-size:12px">${t.desc}</span>
          <span class="tcheck">${t.key === cur ? "✓ 使用中" : ""}</span></div>
      </div>`).join("")}
    </div>`,
    async () => { /* 选择即生效，无需保存 */ }, { okText: "完 成" });
  document.querySelectorAll("[data-theme-key]").forEach(el => el.onclick = () => {
    applyTheme(el.dataset.themeKey);
    document.querySelectorAll("[data-theme-key]").forEach(x => {
      x.classList.toggle("on", x === el);
      const c = x.querySelector(".tcheck"); if (c) c.textContent = x === el ? "✓ 使用中" : "";
    });
  });
}

/* ================= 基础工具 ================= */
async function api(path, opts = {}) {
  const init = {
    method: opts.method || (opts.body ? "POST" : "GET"),
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  };
  if (token) init.headers["Authorization"] = "Bearer " + token;
  if (opts.body) init.body = JSON.stringify(opts.body);
  const res = await fetch(API_BASE + path, init);
  const data = await res.json();
  if (data.code === 401) { logout(true); throw new Error("未登录"); }
  if (data.code === 402) { licenseBlocked(data.msg); throw new Error(data.msg); }
  return data;
}
/* 授权过期：统一提示并跳到授权管理页 */
let _licJumping = false;
function licenseBlocked(msg) {
  toast(msg || "授权已失效，请激活许可", false);
  if (_licJumping) return;
  _licJumping = true;
  setTimeout(() => { _licJumping = false; enter("license"); }, 300);
}
/* 文件上传（multipart，不设 Content-Type 由浏览器生成 boundary） */
async function apiUpload(path, formData, method = "POST") {
  const headers = {};
  if (token) headers["Authorization"] = "Bearer " + token;
  const res = await fetch(API_BASE + path, { method, headers, body: formData, credentials: "include" });
  const data = await res.json();
  if (data.code === 401) { logout(true); throw new Error("未登录"); }
  return data;
}
function toast(msg, ok = true) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.background = ok ? "#1f2d3d" : "#f56c6c";
  t.style.display = "block";
  clearTimeout(t._h); t._h = setTimeout(() => t.style.display = "none", 2800);
}
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function badge(st, okText = "启用", offText = "禁用") { return st ? `<span class="badge ok">${okText}</span>` : `<span class="badge off">${offText}</span>`; }
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false }) : "-"; }
function fmtBytes(n) {
  if (!n && n !== 0) return "-";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = +n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtOnline(sec) {
  if (!sec || sec < 0) return "-";
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + "天" : "") + (h ? h + "小时" : "") + m + "分钟";
}
function errBox(msg) { return `<div class="err-box">⚠ ${esc(msg)}</div>`; }
const fv = id => document.getElementById(id)?.value ?? "";
// 地址类输入：域名或 IP（可带端口/路径）统一补成 https:// 形式。
// 管理页只提供 HTTPS，因此 http:// 会升级；已带 https:// 的只去掉尾部斜杠。
function normalizeHttps(v) {
  let s = (v || "").trim();
  if (!s) return "";                       // 留空保持留空（扫码回调留空=联动公网地址）
  if (/^http:\/\//i.test(s)) s = "https://" + s.slice(7);
  else if (!/^https:\/\//i.test(s)) s = "https://" + s.replace(/^\/+/, "");
  return s.replace(/\/+$/, "");
}
// 输入框失焦时即时回填，所见即所得
function autoHttps(el) { if (el && el.value.trim()) el.value = normalizeHttps(el.value); }
// 复选框取值：checkbox 的 .value 恒为 "on"（与勾选状态无关），必须读 .checked
const fc = id => (document.getElementById(id)?.checked ? 1 : 0);

function confirmModal(title, body, onOk) {
  closeModal("mConfirm");
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mConfirm"><div class="modal" style="width:440px">
    <h3>${esc(title)}</h3><p>${body}</p>
    <div class="actions"><button class="ghost" onclick="closeModal('mConfirm')">取 消</button>
    <button class="red" id="mOkBtn">确 认</button></div></div></div>`);
  document.getElementById("mOkBtn").onclick = async () => { closeModal("mConfirm"); await onOk(); };
}
function closeModal(id) { document.getElementById(id)?.remove(); }
function formModal(title, fieldsHTML, onOk, opts = {}) {
  closeModal("mForm");
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mForm"><div class="modal" ${opts.width ? `style="width:${opts.width}px"` : ""}>
    <h3>${esc(title)}</h3>${fieldsHTML}
    <div class="actions"><button class="ghost" onclick="closeModal('mForm')">取 消</button>
    <button class="primary" id="mSaveBtn">${opts.okText || "保 存"}</button></div></div></div>`);
  document.getElementById("mSaveBtn").onclick = async () => {
    try { await onOk(); closeModal("mForm"); } catch (e) { toast(e.message, false); }
  };
}
const loading = "<div class='page-loading'><span class='spin'></span>加载中…</div>";

/* ================= 登录页 ================= */
function renderLogin() {
  $app.innerHTML = `<div class="login-wrap"><div class="login-card">
    <h1>${brandHTML(30)} ${esc(BRAND.name)}</h1>
    <p class="sub">${esc(BRAND.name)} 管理系统</p>
    <div class="form-row"><label>用户名</label><input id="lgUser" autocomplete="username" placeholder="请输入用户名"></div>
    <div class="form-row"><label>密　码</label><input id="lgPass" type="password" autocomplete="current-password" placeholder="请输入密码"></div>
    <div class="form-row" id="capRow" style="display:none"><label>验证码</label><div class="inline" style="flex:1"><input id="lgCap" placeholder="验证码" style="flex:1"><span id="capBox"></span></div></div>
    <button class="primary" id="lgBtn" style="width:100%;justify-content:center;padding:11px">登 录</button>
    <div style="text-align:center;margin-top:14px"><a class="lk" href="/downloads" target="_blank" rel="noopener">⬇ 客户端下载</a><span class="muted" style="font-size:12px">（自动识别你的系统）</span></div>
  </div>${loginFooterHTML()}</div>`;
  loadCaptcha();
  document.getElementById("lgBtn").onclick = doLogin;
  // 用户名 / 密码 / 验证码任意一处按回车都直接登录（验证码通常是最后填的那一格）
  const onEnter = e => { if (e.key === "Enter") { e.preventDefault(); doLogin(); } };
  ["lgUser", "lgPass", "lgCap"].forEach(id => document.getElementById(id).addEventListener("keydown", onEnter));
}
let capID = "";
let loginPending = false;
async function loadCaptcha() {
  try {
    const d = await api("/captcha");
    if (d.data?.svg) {
      capID = d.data.code_id;
      document.getElementById("capRow").style.display = "flex";
      document.getElementById("capBox").innerHTML = d.data.svg;
    }
  } catch (e) { /* 验证码不可用则跳过 */ }
}
async function doLogin() {
  if (loginPending) return;               // 防止连按回车 / 回车后再次点击造成重复提交
  loginPending = true;
  const btn = document.getElementById("lgBtn");
  if (btn) btn.disabled = true;
  try {
    const r = await api("/logincheck", { body: {
      username: fv("lgUser"), password: fv("lgPass"), captcha: fv("lgCap"), code_id: capID } });
    if (r.code === 1) { token = r.data.token; localStorage.setItem("sslvpn_token", token); enter("dash"); }
    else {
      toast(r.msg, false);
      const cap = document.getElementById("lgCap");
      if (cap) cap.value = "";            // 验证码一次性消费，失败后清空便于直接重输
      loadCaptcha();
    }
  } finally {
    loginPending = false;
    const b = document.getElementById("lgBtn");
    if (b) b.disabled = false;
  }
}
function logout(silent) {
  if (!silent) api("/logout").catch(() => {});
  token = ""; localStorage.removeItem("sslvpn_token");
  renderLogin();
}

/* ================= 主布局（分组侧栏 + 顶栏） ================= */
const NAV = [
  { title: "运行监控", pages: [["dash", "◎", "运行概览"]] },
  { title: "用户与权限", pages: [["users", "👤", "用户账号"], ["ccd", "⚙", "用户策略"], ["ldap", "🔑", "LDAP 目录"], ["online", "📶", "在线会话"]] },
  { title: "连接管理", pages: [["groups", "🗂", "用户分组"], ["services", "🖧", "连接配置"], ["domain", "🌐", "域名分流"]] },
  { title: "系统设置", pages: [["backup", "💾", "备份恢复"], ["clientdl", "⬇", "客户端下载"], ["smtp", "✉", "邮件服务"], ["sso", "🪪", "扫码登录"], ["sys", "☑", "全局设置"], ["fw", "🧱", "访问控制"], ["admins", "🛡", "管理员"], ["license", "🔐", "许可管理"], ["cert", "🔒", "证书管理"]] },
  { title: "日志审计", pages: [["authlog", "📋", "认证日志"], ["syslog", "📄", "系统日志"]] },
];
const ROUTES = { dash: pageDash, users: pageUsers, ccd: pageCcd, ldap: pageLdap, online: pageOnline,
  groups: pageGroups, services: pageServices, backup: pageBackup, smtp: pageSmtp, sys: pageSys,
  fw: pageFW, authlog: pageAuthLog, syslog: pageSysLog, license: pageLicense, admins: pageAdmins, cert: pageCert,
  sso: pageFeishu, domain: pageDomain, clientdl: pageClientDownload };

function renderLayout(page) {
  $app.innerHTML = `
  <div class="header">
    <div class="brand">${brandHTML(26)} <span style="color:var(--primary);font-style:italic">${esc(BRAND.name)}</span>&nbsp;<span style="color:var(--sub);font-style:italic">管理系统</span></div>
    <div class="spacer"></div>
    <div class="btn-exit" id="btnTheme">🎨 主题</div>
    <div class="btn-exit" id="btnGlobal">⚙ 全局配置</div>
    <div class="who">您好，<b>管理员</b></div>
    <div class="btn-exit" id="btnLogout">⏻ 注销登录</div>
  </div>
  <div class="layout">
    <div class="sidebar">
      ${NAV.map(g => `<div class="grp-title">${g.title}</div>
        ${g.pages.map(([k, ico, t]) => `<a data-nav="${k}" class="${k === page ? "active" : ""}"><span>${ico}</span>${t}</a>`).join("")}
        <div class="sep"></div>`).join("")}
    </div>
    <div class="main" id="main"></div>
  </div>${footerHTML()}`;
  document.querySelectorAll("[data-nav]").forEach(a => a.onclick = () => enter(a.dataset.nav));
  document.getElementById("btnLogout").onclick = () => logout(false);
  document.getElementById("btnGlobal").onclick = globalCfgModal;
  document.getElementById("btnTheme").onclick = themeModal;
}
async function globalCfgModal() {
  const d = await api("/linuxcc/get");
  const g = (d.data || {});
  formModal("全局配置", `
    <div class="tip-banner">ⓘ 这里是全局生效的基础参数：<b>公网地址</b>用于生成客户端配置的 remote 行；<b>DNS</b> 会推送给所有 VPN 客户端；<b>下载地址</b>供邮件模板 <code>{download_url}</code> 引用。地址栏填域名或 IP 均可，<b>会自动补上 https://</b>（后端生成 .ovpn 时会自动去掉协议）。修改后对新建连接、重新下发的用户配置生效，已下发的旧配置需重新下载。</div>
    <div class="form-row"><label class="req">公网地址</label><input id="gcHost" value="${esc(normalizeHttps(g.public_host))}" placeholder="vpn.example.com 或 1.2.3.4:58443（自动补 https://）" onblur="autoHttps(this)"></div>
    <div class="form-row"><label>DNS1</label><input id="gcDns1" value="${esc(g.dns1 || "")}" placeholder="114.114.114.114（留空则不推送）"></div>
    <div class="form-row"><label>DNS2</label><input id="gcDns2" value="${esc(g.dns2 || "")}" placeholder="8.8.8.8（留空则不推送）"></div>
    <div class="form-row"><label>客户端下载地址</label><input id="gcDl" value="${esc(g.download_url || "")}" placeholder="域名或 IP，自动补 https://（邮件模板 {download_url} 引用）" onblur="autoHttps(this)"></div>
    <div class="form-row"><label>版权信息</label><input id="gcCP" value="${esc(g.copyright || "")}" placeholder="留空显示默认：© 2026-至今 Power by KingStronger"></div>
    <div class="form-row"><label>版权链接</label><input id="gcCPURL" value="${esc(g.copyright_url || "")}" placeholder="域名或 IP，自动补 https://" onblur="autoHttps(this)"></div>`,
    async () => {
      const r = await api("/linuxcc/update", { body: {
        public_host: normalizeHttps(fv("gcHost")), dns1: fv("gcDns1"), dns2: fv("gcDns2"), download_url: normalizeHttps(fv("gcDl")),
        copyright: fv("gcCP"), copyright_url: normalizeHttps(fv("gcCPURL")) } });
      if (r.code !== 1) throw new Error(r.msg);
      BRAND.copyright = fv("gcCP");
      BRAND.copyright_url = fv("gcCPURL");
      refreshFooter();
      toast("全局配置已保存（新建连接 / 重新下发用户配置后生效）");
    });
}
async function enter(page) {
  renderLayout(page);
  const main = document.getElementById("main");
  main.innerHTML = loading;
  try { await ROUTES[page](main); }
  catch (e) { main.innerHTML = errBox(e.message || "页面加载失败"); }
}

/* ================= 系统信息（仪表盘） ================= */
async function pageDash(main) {
  const d = await api("/account/systeminfo");
  if (d.code !== 1 || !d.data) throw new Error(d.msg || "系统信息获取失败");
  sysInfo = d.data;
  const s = sysInfo;
  const g = (k, def) => (s[k] === undefined || s[k] === null || s[k] === "" ? def : s[k]);
  const now = new Date();
  const week = "日一二三四五六"[now.getDay()];
  const [users, online] = await Promise.all([
    api("/account/userlist").catch(() => ({ data: { list: [] } })),
    api("/log/status").catch(() => ({ data: { list: [] } })),
  ]);
  const hour = now.getHours();
  const hello = hour < 6 ? "凌晨好" : hour < 9 ? "早上好" : hour < 12 ? "上午好" : hour < 14 ? "中午好" : hour < 18 ? "下午好" : "晚上好";
  const bar = (pct, color) => `<div class="inline" style="gap:8px"><div style="flex:1;height:8px;background:#f0f2f5;border-radius:4px;overflow:hidden"><div style="width:${Math.min(pct,100)}%;height:100%;background:${color};border-radius:4px"></div></div><span class="muted" style="font-size:12px">${pct}%</span></div>`;
  main.innerHTML = `
  <div class="topbar">
    <h2>运行概览</h2>
    <div class="inline">
      <button class="ghost small" onclick="enter('dash')">⟳ 刷新</button>
      <button class="primary small" onclick="enter('users')">＋ 新建用户</button>
      <span class="muted" style="font-size:12.5px;margin-left:4px">系统版本 <b style="color:var(--primary)">${esc(g("version", "-"))}</b></span>
    </div>
  </div>

  <div class="card" style="display:flex;align-items:center;gap:10px;padding:14px 22px">
    <div style="flex:1">尊敬的 "<b>管理员</b>" ${hello}，现在是${now.getFullYear()}年${now.getMonth() + 1}月${now.getDate()}日 ${now.getHours()}:${String(now.getMinutes()).padStart(2, "0")} 星期${week}，这是您第 <b style="color:var(--primary)">${esc(g("login_count", "1"))}</b> 次登录 ${esc(BRAND.name)} 管理系统。</div>
  </div>

  <div class="stat-grid">
    <div class="stat"><div class="ico" style="background:linear-gradient(140deg,#0f766e,#12a594)">👤</div>
      <div><div class="num">${g("user_total", 0)}</div>
        <div class="label">用户总数 · 可用 ${g("user_enabled", 0)} · 在线 <b style="color:var(--green)">${g("user_online", 0)}</b></div></div></div>
    <div class="stat"><div class="ico" style="background:linear-gradient(140deg,#0e7490,#22a2b8)">🖧</div>
      <div><div class="num">${g("service_total", 0)}</div>
        <div class="label">连接配置 · 运行中 ${g("service_running", 0)} · 分组 ${g("group_total", 0)}</div></div></div>
    <div class="stat"><div class="ico" style="background:linear-gradient(140deg,#b45309,#d97706)">⚡</div>
      <div><div class="num">${g("mem_percent", 0)}%</div>
        <div class="label">内存占用 · 负载 ${esc(g("load1", "-"))}</div></div></div>
    <div class="stat"><div class="ico" style="background:linear-gradient(140deg,#15803d,#22a05a)">💾</div>
      <div><div class="num">${g("disk_percent", 0)}%</div>
        <div class="label">磁盘占用 · 共 ${g("disk_total_gb", 0)}G · 可用 ${g("disk_free_gb", 0)}G</div></div></div>
  </div>

  <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
    <div class="card" style="flex:2;min-width:320px">
      <h3>✎ 其它信息</h3>
      <table><tr><th style="width:60px">编号</th><th>名称</th><th>记录值</th></tr>
        <tr><td>1</td><td>运行的实例数</td><td><span class="badge blue">${g("service_running", 0)}</span></td></tr>
        <tr><td>2</td><td>连接数/分组数</td><td><span class="badge ok">${g("service_total", 0)}/${g("group_total", 0)}</span></td></tr>
        <tr><td>3</td><td>VPN服务版本</td><td>OpenVPN ${esc(g("openvpn_version", "-"))}</td></tr>
        <tr><td>4</td><td>服务器IP地址</td><td>${esc(g("server_ip", "-"))}</td></tr>
        <tr><td>5</td><td>主机名</td><td>${esc(g("hostname", "-"))}</td></tr>
        <tr><td>6</td><td>系统类型/持续运行</td><td>${s.os_type === "linux" ? "Linux" : esc(g("os_type", "-"))} / ${esc(g("uptime", "-"))}</td></tr>
        <tr><td>7</td><td>数据库</td><td>SQLite（${esc(g("pki_dir", "-"))}）</td></tr>
        <tr><td>8</td><td>系统当前时间</td><td>${esc(g("now", "-"))}</td></tr>
      </table>
    </div>
    <div class="card" style="flex:1;min-width:300px">
      <h3>💡 使用步骤 <span class="hint">首次部署按序执行</span></h3>
      <ol style="line-height:2.05;color:#606266;padding-left:18px;font-size:13px">
        <li>点击右上角 <b>⚙ 全局配置</b>，确认<b>服务器公网地址</b>正确（用于生成客户端配置）。</li>
        <li>连接管理 → <b>用户分组</b> → 添加分组。</li>
        <li>连接管理 → <b>连接配置</b> → 添加连接。</li>
        <li>连接管理 → <b>连接配置</b> → 关联分组。</li>
        <li>用户与权限 → <b>用户账号</b> → 添加用户（或从 LDAP 目录同步）。</li>
        <li>下载用户配置文件，导入客户端连接测试。</li>
      </ol>
    </div>
  </div>
  <div class="card">
    <h3>📶 在线会话 <span class="hint">共 ${online.data.count ?? 0} 人</span></h3>
    <div id="dashOnline"></div>
  </div>`;
  renderOnlineTable(document.getElementById("dashOnline"), online.data.list || []);
}

/* ================= 用户配置 ================= */
let groupMap = {};
async function pageUsers(main) {
  const g = await api("/group/list");
  groupMap = {}; (g.data.list || []).forEach(x => groupMap[x.id] = x.name);
  const kw = fv("uKw");
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">👤 VPN 用户列表</h3>
      <div class="inline">
        <button class="primary" onclick="userAddModal()">＋ 添加用户</button>
        <button class="ghost" onclick="window.open(API_BASE + '/account/exportDatabase')">📤 导出用户数据表格</button>
        <button class="ghost" onclick="enter('users')">⟳ 刷新</button>
      </div></div>
    <div class="inline" style="margin-bottom:12px">
      <input id="uKw" placeholder="请输入 VPN 用户名" value="${esc(kw)}" style="width:220px"
        onkeydown="if(event.key==='Enter')enter('users')">
      <button class="primary" onclick="enter('users')">🔍 搜索</button>
    </div>
    <p class="muted" style="margin:-4px 0 12px">客户端登录请使用「VPN用户名」列的值；「联系邮箱」只用于接收账号邮件，<b>不是登录账号</b>。若需以邮箱登录，请在「LDAP 用户同步」把搜索过滤器改为 <code>(mail=%s)</code> 后重新同步用户。</p>
    <div id="userTable">${loading}</div></div>`;
  const d = await api("/account/userlist?keyword=" + encodeURIComponent(kw));
  const list = d.data.list || [];
  const authName = { local: "本地密码", totp: "TOTP 动态码", ldap: "LDAP存储", feishu: "扫码登录", sso: "扫码登录", dingtalk: "扫码登录", wecom: "扫码登录" };
  const rows = list.map(a => `<tr>
    <td>${esc(a.username)}</td>
    <td>${esc(a.password === "-" ? "•••••" : a.password)}</td>
    <td>${esc(a.email || "-")}</td>
    <td>${a.online ? '<span class="badge ok">在线</span>' : '<span class="badge gray">离线</span>'}</td>
    <td>${a.online && a.virtual_ip
      ? `<b style="color:var(--primary)" title="来源 IP: ${esc(a.real_ip || "-")}">${esc(a.virtual_ip)}</b>`
      : '<span class="muted">-</span>'}</td>
    <td>${badge(a.status)}</td>
    <td><span class="badge ${["ldap","feishu","sso","dingtalk","wecom"].indexOf(a.auth_type) >= 0 ? "blue" : "gray"}">${authName[a.auth_type] || esc(a.auth_type)}</span></td>
    <td>${a.group_id && groupMap[a.group_id] ? esc(groupMap[a.group_id]) : '<span class="muted">未分配</span>'}</td>
    <td>${a.expire_date || "永久"}</td>
    <td class="muted">${esc(a.created_at || "-")}</td>
    <td class="inline" style="flex-wrap:nowrap">
      <a href="javascript:;" class="lk" onclick="userEditModal(${a.id})">编辑</a>
      <a href="javascript:;" class="lk g" onclick="userDetail(${a.id})">详情</a>
      <a href="javascript:;" class="lk g" onclick="userDownload(${a.id},'${esc(a.username)}')">下载配置</a>
      <a href="javascript:;" class="lk o" onclick="userMail(${a.id})">邮件</a>
      <a href="javascript:;" class="lk r" onclick="userDel(${a.id},'${esc(a.username)}')">删除</a>
    </td></tr>`).join("");
  document.getElementById("userTable").innerHTML = list.length ? `<table>
    <tr><th>VPN用户名</th><th>密码</th><th>联系邮箱<br><span class="muted" style="font-weight:normal">仅发邮件用</span></th><th>在线状态</th><th>客户端IP</th><th>用户状态</th><th>认证类型</th><th>所属分组</th><th>过期时间</th><th>创建时间</th><th>功能操作</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无用户，点击右上角"添加用户"创建，或从 LDAP配置 → 同步用户 导入</p>`;
}
/* 生成强随机密码（与服务端 util.RandomPassword 规则一致：大小写+数字，排除易混淆字符） */
function genStrongPwd(n = 12) {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", lower = "abcdefghijkmnopqrstuvwxyz", digit = "23456789";
  const all = upper + lower + digit;
  const rnd = max => {
    const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % max;
  };
  const pick = s => s[rnd(s.length)];
  const out = [pick(upper), pick(lower), pick(digit)];
  while (out.length < n) out.push(pick(all));
  for (let i = out.length - 1; i > 0; i--) { const j = rnd(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join("");
}
async function userAddModal() {
  await ensureGroupOpts();
  formModal("添加 VPN 用户", `
    <div class="form-row"><label class="req">用户名</label><input id="uaName" maxlength="64" placeholder="字母 / 数字 / _ . -，最长 64 位"></div>
    <div class="form-row"><label>密码</label>
      <div class="inline" style="flex:1;gap:8px">
        <input id="uaPass" style="flex:1" placeholder="留空自动生成 12 位强密码（大小写+数字）">
        <button class="ghost small" onclick="document.getElementById('uaPass').value=genStrongPwd()">🎲 随机</button>
      </div></div>
    <div class="form-row"><label>认证类型</label><select id="uaType" onchange="uaTypeChanged()"><option value="local">本地密码</option><option value="totp">TOTP 动态码</option><option value="ldap">LDAP</option><option value="sso">扫码登录（飞书/钉钉/企微）</option></select></div>
    <div class="form-row"><label>联系邮箱</label><input id="uaMail" placeholder="用于发送账号信息（不是登录账号）"></div>
    <div class="form-row"><label>登录别名<br><span class="muted" style="font-weight:normal">UPN / DN</span></label><input id="uaAlias" placeholder="如 zhangsan@example.com，多个用逗号分隔"></div>
    <div class="form-row"><label>所属分组</label><select id="uaGrp">${groupOpts}</select></div>
    <div class="form-row"><label>到期日期</label><input id="uaExp" type="date"></div>
    <div class="form-row"><label>备注</label><input id="uaNote"></div>`,
    async () => {
      const r = await api("/account/add", { body: {
        username: fv("uaName"), password: fv("uaPass"), auth_type: fv("uaType"),
        email: fv("uaMail"), login_aliases: fv("uaAlias"),
        expire_date: fv("uaExp"), group_id: +fv("uaGrp") || 0, note: fv("uaNote") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("创建成功，密码: " + (r.data?.password || "见用户详情"));
      enter("users");
    });
}
let groupOpts = "";
async function ensureGroupOpts() {
  if (groupOpts) return;
  const g = await api("/group/list");
  groupOpts = `<option value="0">未分组</option>` + (g.data.list || []).map(x =>
    `<option value="${x.id}">${esc(x.name)}</option>`).join("");
}
async function userEditModal(id) {
  const d = await api("/account/userlist?keyword=");
  const a = (d.data.list || []).find(x => x.id === id);
  if (!a) return;
  await ensureGroupOpts();
  formModal("编辑用户：" + esc(a.username), `
    <div class="form-row"><label>密码</label>
      <div class="inline" style="flex:1;gap:8px">
        <input id="uePass" style="flex:1" ${["ldap","feishu","sso","dingtalk","wecom"].indexOf(a.auth_type) >= 0 ? "disabled" : ""}
          value="${esc(a.password === "-" ? "" : a.password)}"
          placeholder="${a.auth_type === "ldap" ? "LDAP 统一认证，密码由域服务校验，不可在此设置" : (["feishu","sso","dingtalk","wecom"].indexOf(a.auth_type) >= 0 ? "扫码登录，无需密码" : "可留空；点右侧按钮生成 12 位强密码")}">
        <button class="ghost small" ${a.auth_type === "ldap" ? "disabled" : ""} onclick="document.getElementById('uePass').value=genStrongPwd()">🎲 随机</button>
      </div></div>
    <div class="form-row"><label>邮箱</label><input id="ueMail" value="${esc(a.email)}"></div>
    <div class="form-row"><label>登录别名<br><span class="muted" style="font-weight:normal">UPN / DN</span></label><input id="ueAlias" value="${esc(a.login_aliases || "")}" placeholder="如 zhangsan@example.com，多个用逗号分隔"></div>
    <div class="form-row"><label>所属分组</label><select id="ueGrp">${groupOpts}</select></div>
    <div class="form-row"><label>到期日期</label><input id="ueExp" type="date" value="${esc(a.expire_date)}"></div>
    <div class="form-row"><label>状态</label><select id="ueSt"><option value="1" ${a.status ? "selected" : ""}>启用</option><option value="0" ${a.status ? "" : "selected"}>禁用</option></select></div>
    <div class="form-row"><label>备注</label><input id="ueNote" value="${esc(a.note)}"></div>`,
    async () => {
      const r = await api("/account/update", { body: { id, username: a.username, password: fv("uePass"),
        email: fv("ueMail"), login_aliases: fv("ueAlias"),
        expire_date: fv("ueExp"), group_id: +fv("ueGrp") || 0,
        status: +fv("ueSt"), note: fv("ueNote") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("已更新"); enter("users");
    });
  document.getElementById("ueGrp").value = String(a.group_id || 0);
}
async function userDetail(id) {
  const d = await api("/account/showDetail", { body: { id } });
  const a = d.data.user;
  const otp = d.data.otpauth_url ? `<p style="margin-top:8px">TOTP 链接：<code style="word-break:break-all">${esc(d.data.otpauth_url)}</code></p>` : "";
  const on = d.data.online_info ? `<p>在线：${esc(d.data.online_info.real_ip)} → ${esc(d.data.online_info.virtual_ip)}，上线于 ${fmtTime(d.data.online_info.connected_since)}</p>` : "<p class='muted'>当前离线</p>";
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mDetail" onclick="if(event.target===this)closeModal('mDetail')"><div class="modal">
    <h3>用户详情：${esc(a.username)}</h3>
    <p>认证类型：${esc(a.auth_type)}</p><p>邮箱：${esc(a.email || "-")}</p>
    <p>到期：${a.expire_date || "永久"}</p><p>创建：${esc(a.created_at)}</p>${otp}${on}
    <div class="actions"><button class="primary" onclick="closeModal('mDetail')">关 闭</button></div></div></div>`);
}
async function userDownload(id, username) {
  const svc = await api("/service/list");
  const list = (svc.data.list || []);
  if (!list.length) return toast("请先在「服务管理」创建服务实例", false);
  formModal("下载 " + esc(username) + " 的用户配置", `
    <div class="form-row"><label>服务实例</label><select id="udSvc">
    ${list.map(s => `<option value="${esc(s.name)}">${esc(s.name)} (:${s.port}/${esc(s.proto)})</option>`).join("")}</select></div>`,
    async () => {
      const resp = await fetch(API_BASE + "/account/downloadUserCfg", { method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
        body: JSON.stringify({ username, service: fv("udSvc") }) });
      if (resp.headers.get("content-type")?.includes("application/json")) {
        const j = await resp.json(); throw new Error(j.msg || "生成失败");
      }
      const a = document.createElement("a");
      a.href = URL.createObjectURL(await resp.blob());
      a.download = username + ".ovpn"; a.click();
      toast("配置已下载，导入 OpenVPN 客户端即可");
    }, { okText: "下载" });
}
async function userMail(id) {
  const r = await api("/account/sendMail", { body: { id } });
  if (r.code !== 1) return toast(r.msg, false);
  const att = r.data && r.data.attachment && r.data.attachment !== "无" ? `，附件 ${r.data.attachment}` : "（无附件，请检查用户是否已关联服务实例）";
  toast("邮件已发送" + att);
}
function uaTypeChanged() {
  const pass = document.getElementById("uaPass");
  if (!pass) return;
  const isLdap = fv("uaType") === "ldap";
  pass.disabled = isLdap;
  pass.placeholder = isLdap ? "LDAP 统一认证，密码由域服务校验" : "留空自动生成";
  if (isLdap) pass.value = "";
}
function userDel(id, username) {
  confirmModal("删除用户信息", `将删除 <b>${esc(username)}</b> 并吊销其证书，已下发的配置将失效。确定？`, async () => {
    const r = await api("/account/delete", { body: { id } });
    toast(r.msg, r.code === 1); enter("users");
  });
}

/* ================= 高级配置（CCD） ================= */
async function pageCcd(main) {
  const svc = await api("/service/list");
  const opts = (svc.data.list || []).map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join("");
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">⚙ 用户策略</h3>
      <div class="inline">
        <button class="primary" onclick="ccdAddModal()">＋ 添加配置</button>
        <select id="ccdSvc" onchange="renderCcdTable()" style="width:180px"><option value="0">选择一个服务</option>${opts}</select>
        <input id="ccdKw" placeholder="搜索用户名" style="width:180px" oninput="renderCcdTable()">
      </div></div>
    <div id="ccdTable">${loading}</div></div>`;
  renderCcdTable();
}
async function renderCcdTable() {
  const sid = fv("ccdSvc") || "0";
  const kw = (fv("ccdKw") || "").toLowerCase();
  const d = await api("/ccd/?service_id=" + sid);
  const svcList = await api("/service/list");
  const svcName = {}; (svcList.data.list || []).forEach(s => svcName[s.id] = s.name);
  let list = (d.data.list || []);
  if (kw) list = list.filter(c => c.username.toLowerCase().includes(kw));
  const rows = list.map(c => `<tr>
    <td><input type="checkbox"></td>
    <td>${c.id}</td>
    <td><span class="badge blue">${esc(svcName[c.service_id] || c.service_id)}</span></td>
    <td>${esc(c.username)}</td><td>${esc(c.username)}</td>
    <td>${c.ifconfig_push ? `<b style="color:var(--primary)">${esc(c.ifconfig_push)}</b>` : '<span style="color:#e6a23c">未配置</span>'}</td>
    <td class="muted">${esc(c.created_at || "-")}</td>
    <td class="muted">${esc(c.updated_at || "-")}</td>
    <td class="inline" style="flex-wrap:nowrap">
      <a href="javascript:;" class="lk g" onclick="ccdView(${c.id})">查看</a>
      <a href="javascript:;" class="lk" onclick="ccdEditModal(${c.id})">编辑</a>
      <a href="javascript:;" class="lk r" onclick="ccdDel(${c.id})">删除</a></td></tr>`).join("");
  document.getElementById("ccdTable").innerHTML = list.length ? `<table>
    <tr><th></th><th>ID</th><th>服务名称</th><th>使用人</th><th>用户名</th><th>静态IP地址</th><th>创建时间</th><th>更新时间</th><th>操作</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无配置</p>`;
}
async function ccdView(id) {
  const d = await api("/ccd/?service_id=0");
  const c = (d.data.list || []).find(x => x.id === id);
  if (!c) return;
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mCcdV" onclick="if(event.target===this)closeModal('mCcdV')"><div class="modal" style="width:680px">
    <h3>用户策略详情：${esc(c.username)}</h3><pre class="log">${esc(c.content || "# 空")}</pre>
    <p class="muted" style="margin-top:6px">以上为该用户实际生效的 CCD 文件内容，修改后用户重新连接 VPN 生效。</p>
    <div class="actions"><button class="primary" onclick="closeModal('mCcdV')">关 闭</button></div></div></div>`);
}
/* ---------- 用户名自动搜索（下拉过滤） ---------- */
let AC_SRC = [];      // 候选列表
let AC_INPUT = null;  // 当前绑定的输入框
function acBind(inputId, users) {
  AC_SRC = users || [];
  AC_INPUT = document.getElementById(inputId);
  if (!AC_INPUT) return;
  AC_INPUT.addEventListener("input", acRender);
  AC_INPUT.addEventListener("focus", acRender);
  AC_INPUT.addEventListener("blur", () => setTimeout(acHide, 150));
}
function acRender() {
  const drop = document.getElementById("acDrop");
  if (!drop || !AC_INPUT) return;
  const kw = AC_INPUT.value.trim().toLowerCase();
  const list = AC_SRC.filter(u => !kw || u.toLowerCase().includes(kw)).slice(0, 60);
  if (!list.length) { drop.style.display = "none"; return; }
  drop.innerHTML = list.map(u =>
    `<div class="ac-item" onmousedown="acPick('${esc(u)}')">${esc(u)}</div>`).join("");
  drop.style.display = "block";
}
function acPick(u) {
  if (AC_INPUT) { AC_INPUT.value = u; AC_INPUT.dispatchEvent(new Event("input")); }
  acHide();
}
function acHide() {
  const drop = document.getElementById("acDrop");
  if (drop) drop.style.display = "none";
}
function acFieldHTML(inputId, placeholder) {
  return `<div class="ac-wrap"><input id="${inputId}" autocomplete="off" placeholder="${placeholder || "输入名称搜索"}">
    <div class="ac-drop" id="acDrop" style="display:none"></div></div>`;
}
// 前端预览：由结构化字段生成 CCD 内容（与后端 RenderCcd 逻辑一致）
function ccdRenderLocal(c) {
  const out = [];
  if (+c.proxy_mode === 2) out.push("# 仅内网：忽略服务实例的全局代理等推送", "push-reset");
  if (c.ifconfig_push) out.push("ifconfig-push " + c.ifconfig_push);
  (c.iroutes || "").split("\n").map(x => x.trim()).filter(Boolean).forEach(l => out.push("iroute " + l));
  if (+c.proxy_mode === 1) out.push('push "redirect-gateway def1 bypass-dhcp"');
  const dnsList = (c.dns || "").split(/[\s,]+/).filter(Boolean);
  dnsList.forEach(d => out.push('push "dhcp-option DNS ' + d + '"'));
  if (+c.proxy_mode === 1 && !dnsList.length) out.push("# 未单独填写 DNS：将沿用「全局设置 → DNS」中的地址");
  (c.push_routes || "").split("\n").map(x => x.trim()).filter(Boolean).forEach(l => {
    if (/^push(\s|$)/.test(l) || l === "push-reset") out.push(l);
    else out.push('push "route ' + l + '"');
  });
  return out.join("\n") || "# 空";
}
const CCD_RAW_TIP = `# 原始 CCD 配置（保存后按此文件内容生效，# 开头为注释）
# 1. 指定静态 IP（可选）： ifconfig-push 10.8.0.100 255.255.255.0
# 2. 推送路由（可多行）：  push "route 172.16.10.0 255.255.255.0"
# 3. 推送 DNS：            push "dhcp-option DNS 223.5.5.5"
# 4. 全局代理（所有流量走 VPN）：push "redirect-gateway def1 bypass-dhcp"
# 5. 忽略服务实例的所有推送（仅用本文件）：push-reset`;
function ccdFieldsHTML(pfx, c) {
  c = c || {};
  return `
    <div class="form-row"><label>代理模式</label><select id="${pfx}Proxy">
      <option value="0" ${+c.proxy_mode === 0 ? "selected" : ""}>继承服务实例（跟随服务配置）</option>
      <option value="1" ${+c.proxy_mode === 1 ? "selected" : ""}>全局代理（该用户全部流量 + DNS 走 VPN）</option>
      <option value="2" ${+c.proxy_mode === 2 ? "selected" : ""}>仅内网路由（忽略全局代理，其余走本地）</option></select></div>
    <div class="form-row"><label>静态 IP</label><input id="${pfx}IP" value="${esc(c.ifconfig_push || "")}" placeholder="10.8.0.100 255.255.255.0（可空）"></div>
    <div class="form-row"><label>DNS 服务器</label><input id="${pfx}Dns" value="${esc(c.dns || "")}" placeholder="223.5.5.5,114.114.114.114（可多个，仅推送给该用户）"></div>
    <div class="form-row"><label>iroute</label><textarea id="${pfx}Iroute" placeholder="每行一条：网段 掩码（声明该用户身后可达的网段）">${esc(c.iroutes || "")}</textarea></div>
    <div class="form-row"><label>push route</label><textarea id="${pfx}Push" placeholder="每行一条：网段 掩码；也可直接写 push &quot;...&quot; 指令">${esc(c.push_routes || "")}</textarea></div>
    <div class="form-row"><label>原始配置</label><div>
      <label style="display:inline-flex;align-items:center;gap:6px;margin-bottom:6px">
        <input type="checkbox" id="${pfx}RawChk" onchange="ccdRawToggle('${pfx}')"> 启用原始配置编辑（高级，与旧版一致，勾选后以上面字段生成的预览为基础自由修改）</label>
      <textarea id="${pfx}Raw" style="display:none;font-family:monospace;min-height:170px" placeholder="${esc(CCD_RAW_TIP)}"></textarea></div></div>`;
}
function ccdRawToggle(pfx) {
  const chk = document.getElementById(pfx + "RawChk"), ta = document.getElementById(pfx + "Raw");
  if (!chk || !ta) return;
  ta.style.display = chk.checked ? "block" : "none";
  if (chk.checked && !ta.dataset.edited) {
    ta.value = ccdRenderLocal({ proxy_mode: fv(pfx + "Proxy"), ifconfig_push: fv(pfx + "IP"),
      dns: fv(pfx + "Dns"), iroutes: fv(pfx + "Iroute"), push_routes: fv(pfx + "Push") });
    ta.dataset.edited = "1";
  }
}
function ccdCollect(pfx) {
  const rawChk = document.getElementById(pfx + "RawChk");
  return { ifconfig_push: fv(pfx + "IP"), iroutes: fv(pfx + "Iroute"), push_routes: fv(pfx + "Push"),
    dns: fv(pfx + "Dns"), proxy_mode: +fv(pfx + "Proxy") || 0,
    raw: rawChk && rawChk.checked ? document.getElementById(pfx + "Raw").value : "" };
}
async function ccdAddModal() {
  const svc = await api("/service/list");
  const users = await api("/ccd/getAllUser");
  const opts = (svc.data.list || []).map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join("");
  formModal("添加 CCD 配置", `
    <div class="form-row"><label class="req">服务实例</label><select id="ccSvc">${opts}</select></div>
    <div class="form-row"><label class="req">用户名</label>${acFieldHTML("ccUser", "输入用户名搜索（支持模糊匹配）")}</div>
    ${ccdFieldsHTML("cc")}`,
    async () => {
      if (!fv("ccUser")) throw new Error("请填写用户名");
      const r = await api("/ccd/addccdCfg", { body: { service_id: +fv("ccSvc"), username: fv("ccUser"), ...ccdCollect("cc") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("已创建，用户重新连接 VPN 后生效"); enter("ccd");
    });
  acBind("ccUser", users.data.users || []);
}
async function ccdEditModal(id) {
  const d = await api("/ccd/?service_id=0");
  const c = (d.data.list || []).find(x => x.id === id);
  if (!c) return;
  const svc = await api("/service/list");
  formModal("编辑 CCD：" + esc(c.username), `
    <div class="form-row"><label>服务实例</label><select id="ceSvc" disabled>${svc.data.list.map(s =>
      `<option value="${s.id}" ${s.id === c.service_id ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select></div>
    ${ccdFieldsHTML("ce", c)}`,
    async () => {
      const r = await api("/ccd/update", { body: { id, ...ccdCollect("ce") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("已更新，用户重新连接 VPN 后生效"); enter("ccd");
    });
  if (c.raw && c.raw.trim()) {
    const chk = document.getElementById("ceRawChk");
    chk.checked = true; ccdRawToggle("ce");
    document.getElementById("ceRaw").value = c.raw;
    document.getElementById("ceRaw").dataset.edited = "1";
  } else if ((c.content || "").trim() && c.content.trim() !== "# 空") {
    document.getElementById("ceRaw").value = c.content;
  }
}
function ccdDel(id) {
  confirmModal("删除 CCD 配置", "确定删除该条配置？", async () => {
    const r = await api("/ccd/remove?id=" + id, { method: "DELETE" });
    toast(r.msg, r.code === 1); enter("ccd");
  });
}

/* ================= LDAP 配置 ================= */
async function pageLdap(main) {
  const d = await api("/ldap/get");
  const c = d.data;
  main.innerHTML = `<div class="card" style="max-width:900px">
    <h3>🔑 LDAP 用户同步</h3>
    <div class="form-row"><label>服务端口号</label><input id="ldPort" type="number" value="${c.port || 389}"></div>
    <div class="form-row"><label>服务器地址</label><input id="ldServer" value="${esc(c.server || "")}" placeholder="ldap://10.5.0.27 或 IP"></div>
    <div class="form-row"><label>基础 DN</label><input id="ldBase" value="${esc(c.base_dn || "")}" placeholder="dc=example,dc=com"></div>
    <div class="form-row"><label>绑定 DN</label><input id="ldBind" value="${esc(c.bind_dn || "")}" placeholder="cn=admin,dc=xxx,dc=xxx"></div>
    <div class="form-row"><label>密码</label><input id="ldPass" type="password" value="${esc(c.bind_pass || "")}"></div>
    <div class="form-row"><label>组织单元 OU</label><input id="ldOU" value="${esc(c.ou || "")}" placeholder="people（可空）"></div>
    <div class="form-row"><label>搜索过滤器</label><div>
      <input id="ldFilter" value="${esc(c.filter || "(uid=%s)")}" placeholder="%s 为用户名占位">
      <div class="muted" style="margin-top:4px">账号形态：AD 域短账号用 <code>(sAMAccountName=%s)</code>，邮箱账号用 <code>(mail=%s)</code> 或 <code>(userPrincipalName=%s)</code>，通用 <code>(uid=%s)</code>。<br>
      <b>改过滤器后必须点「同步用户」重新导入</b>：同步进来的 VPN 用户名取自过滤器属性（如 <code>(mail=%s)</code> 时账号名就是邮箱），客户端也要用同名登录；已有的短名账号不会自动改名，切换过滤器后短名账号将无法通过 LDAP 校验。「联系邮箱」只用于发邮件，不是登录账号。</div>
      <div class="inline" style="margin-top:6px">
        <button class="ghost" onclick="document.getElementById('ldFilter').value='(sAMAccountName=%s)'">AD 域账号</button>
        <button class="ghost" onclick="document.getElementById('ldFilter').value='(mail=%s)'">邮箱账号</button>
        <button class="ghost" onclick="document.getElementById('ldFilter').value='(userPrincipalName=%s)'">UPN 账号</button>
      </div>
    </div></div>
    <div class="form-row"><label></label><div class="inline">
      <button class="primary" onclick="ldapSave()">✓ 更新</button>
      <button class="green" onclick="ldapTest()">🔗 测试连接</button>
      <button class="orange" onclick="ldapClear()">⟲ 清除</button>
      <button class="ghost" onclick="enter('ldap')">⟳ 刷新</button>
      <button class="red" onclick="ldapSyncDialog()">⇄ 同步用户</button>
    </div></div>
    <p class="muted" style="margin-top:6px">同步后用户认证类型为 LDAP，密码由 LDAP 服务校验；本地不存密码。</p></div>
  <div class="card" style="max-width:900px">
    <h3>🔐 登录方式 <span class="hint">默认只短账号；管理员可开启邮箱 / UPN(DN) 别名登录</span></h3>
    <div class="tip-banner">ⓘ 别名在服务端解析成真实 VPN 用户名后再校验，<b>LDAP 搜索过滤器保持 <code>(uid=%s)</code> 不用改</b>，客户端也不用更新。配置下发与 OpenVPN 认证两处同时生效。</div>
    <div class="form-row"><label>短账号</label>
      <label style="width:auto;text-align:left"><input type="checkbox" checked disabled> 始终开启（如 <code>zhangsan</code>），不受下方开关影响</label></div>
    <div class="form-row"><label>邮箱账号</label>
      <label style="width:auto;text-align:left"><input type="checkbox" id="laMail"> 用「联系邮箱」登录（多个账号共用同一邮箱时会拒绝，请改用下方 UPN/DN）</label></div>
    <div class="form-row"><label>UPN / DN</label>
      <label style="width:auto;text-align:left"><input type="checkbox" id="laUpn"> 用账号上配置的「登录别名」登录（如 <code>zhangsan</code> ↔ <code>zhangsan@example.com</code>）</label></div>
    <div class="form-row"><label></label>
      <button class="primary" onclick="loginAliasSave()">✓ 保存登录方式</button></div>
    <div class="muted" style="font-size:12px;line-height:1.7">ⓘ 别名在「用户账号 → 添加/编辑用户 → 登录别名」逐账号填写，逗号分隔可填多个。短账号与 DN 常无字符串对应关系，系统<b>不做前缀推导</b>，必须显式配置；显式别名优先于联系邮箱，可绕开邮箱重复带来的歧义。</div>
  </div>`;
  await loginAliasLoad();
}
async function loginAliasLoad() {
  const r = await api("/system/loginAlias/get");
  if (r.code !== 1) return;
  const d = r.data || {};
  const m = document.getElementById("laMail"), u = document.getElementById("laUpn");
  if (m) m.checked = !!d.mail;
  if (u) u.checked = !!d.upn;
}
async function loginAliasSave() {
  const r = await api("/system/loginAlias/save", { body: {
    mail: document.getElementById("laMail").checked,
    upn: document.getElementById("laUpn").checked } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) loginAliasLoad();
}
async function ldapSave() {
  const r = await api("/ldap/update", { body: { server: fv("ldServer"), port: +fv("ldPort"),
    bind_dn: fv("ldBind"), bind_pass: fv("ldPass"), base_dn: fv("ldBase"),
    ou: fv("ldOU"), filter: fv("ldFilter"), enabled: 1 } });
  toast(r.msg, r.code === 1);
}
function ldapClear() {
  ["ldServer", "ldBase", "ldBind", "ldPass", "ldOU"].forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
  const f = document.getElementById("ldFilter"); if (f) f.value = "(uid=%s)";
  toast("已清空表单（未保存）");
}
async function ldapTest() {
  toast("正在连接 LDAP 服务器…");
  try {
    const r = await api("/ldap/ping");
    if (r.code === 1) toast("✓ " + r.msg);           // 连接成功，匹配到 N 个用户
    else toast("✗ " + r.msg, false);
  } catch (e) { toast("✗ 请求失败: " + e.message, false); }
}
async function ldapSyncDialog() {
  await ensureGroupOpts();
  closeModal("mLdapSync");
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mLdapSync"><div class="modal ldap-dialog">
    <h3>目录用户列表</h3>
    <div class="tip-banner">ⓘ 提示：不再显示已经存在的用户，包括已禁用的，以用户名为准。</div>
    <div class="ldap-pick">👥 选择分组 <select id="lsGrp" style="width:200px">${groupOpts}</select>
      <input id="lsKw" placeholder="过滤用户名" style="width:160px;margin-left:10px" oninput="ldapRenderRows()"></div>
    <div id="lsTable">${loading}</div>
    <div class="actions left">
      <span class="sel-count" id="lsCount">已选 0 人</span>
      <button class="primary" id="lsImportSel">👥 导入用户</button>
      <button class="green" id="lsImportAll">👥 导入全部</button>
      <button class="danger" onclick="closeModal('mLdapSync')">✕ 取消关闭</button>
    </div></div></div>`);
  let d;
  try {
    d = await api("/ldap/listusers");
  } catch (e) {
    document.getElementById("lsTable").innerHTML = errBox("获取用户列表失败: " + e.message);
    return;
  }
  if (d.code !== 1) {
    document.getElementById("lsTable").innerHTML = errBox(d.msg || "获取用户列表失败（请先保存 LDAP 配置并确认服务器可达）");
    return;
  }
  window._ldapUsers = d.data.list || [];
  window._ldapExists = d.data.exists || {};
  ldapRenderRows();
  document.getElementById("lsImportSel").onclick = () => ldapDoImport(false);
  document.getElementById("lsImportAll").onclick = () => ldapDoImport(true);
}
function ldapRenderRows() {
  const kw = (fv("lsKw") || "").toLowerCase();
  const users = (window._ldapUsers || []).filter(u => !kw || u.username.toLowerCase().includes(kw));
  const rows = users.map((u, i) => {
    const exists = window._ldapExists[u.username];
    return `<tr style="${exists ? "color:#c0c4cc" : ""}">
      <td>${exists ? "" : `<input type="checkbox" class="lsChk" value="${esc(u.username)}" onchange="ldapUpdateCount()">`}</td>
      <td>${esc(u.display_name || "-")}</td><td>${esc(u.username)}</td><td>${esc(u.email || "-")}</td>
      <td>${exists ? '<span class="badge gray">已存在</span>' : '<span class="badge blue">可导入</span>'}</td></tr>`;
  }).join("");
  document.getElementById("lsTable").innerHTML = users.length ? `<table>
    <tr><th><input type="checkbox" id="lsAll" onchange="ldapToggleAll(this)" title="全选"></th>
    <th>使用人名称</th><th>用户名</th><th>邮箱</th><th>状态</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:26px 0">LDAP 中没有可导入的用户</p>`;
  ldapUpdateCount();
}
function ldapToggleAll(box) {
  document.querySelectorAll(".lsChk").forEach(c => { if (!c.disabled) c.checked = box.checked; });
  ldapUpdateCount();
}
function ldapUpdateCount() {
  const el = document.getElementById("lsCount");
  if (!el) return;
  const all = document.querySelectorAll(".lsChk").length;
  const sel = document.querySelectorAll(".lsChk:checked").length;
  el.textContent = sel ? `已选 ${sel} 人` : (all ? `共 ${all} 人可导入` : "");
  const allBox = document.getElementById("lsAll");
  if (allBox) {
    allBox.checked = all > 0 && sel === all;
    allBox.indeterminate = sel > 0 && sel < all;
  }
}
async function ldapDoImport(all) {
  const usernames = all ? (window._ldapUsers || []).filter(u => !window._ldapExists[u.username]).map(u => u.username)
    : [...document.querySelectorAll(".lsChk:checked")].map(x => x.value);
  if (!usernames.length) return toast("请先勾选要导入的用户", false);
  const r = await api("/ldap/import", { body: { usernames, group_id: +fv("lsGrp") || 0 } });
  if (r.code !== 1) return toast(r.msg, false);
  toast(`导入完成：新增 ${r.data.added}，跳过 ${r.data.skipped}`);
  closeModal("mLdapSync");
  enter("users");
}

/* ================= 在线状态 ================= */
async function pageOnline(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">📶 在线会话</h3>
      <div class="inline">
        <button class="primary" onclick="enter('online')">⟳ 获取最新数据</button>
      </div></div>
    <div id="onlineTable">${loading}</div></div>`;
  const d = await api("/log/status");
  renderOnlineTable(document.getElementById("onlineTable"), d.data.list || []);
}
function renderOnlineTable(el, list) {
  el.innerHTML = list.length ? `<table>
    <tr><th>用户名</th><th>真实 IP:端口</th><th>虚拟 IP</th><th>接收字节</th><th>发送字节</th><th>上线时间</th><th>在线时长</th></tr>
    ${list.map(u => { const dur = u.connected_since ? Math.floor(Date.now() / 1000 - u.connected_since) : 0; return `<tr>
      <td>${esc(u.username)}</td><td>${esc(u.real_ip)}</td><td><b style="color:var(--primary)">${esc(u.virtual_ip || "-")}</b></td>
      <td>${fmtBytes(u.bytes_recv)}</td><td>${fmtBytes(u.bytes_send)}</td>
      <td>${u.connected_since ? fmtTime(u.connected_since) : "-"}</td><td>${u.connected_since && dur > 0 ? fmtOnline(dur) : "-"}</td></tr>`; }).join("")}</table>`
    : `<p class="muted" style="text-align:center;padding:40px 0">暂无数据</p>`;
}

/* ================= 分组管理 ================= */
async function pageGroups(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">👥 用户分组</h3>
      <div class="inline"><button class="primary" onclick="groupAddModal()">＋ 添加分组</button>
      <span class="muted">💡 创建分组后，可将多个服务实例关联给整组用户</span></div></div>
    <div id="grpTable">${loading}</div></div>`;
  const d = await api("/group/list");
  const rows = (d.data.list || []).map(g => `<tr>
    <td>${g.id}</td><td><b>${esc(g.name)}</b></td><td>${esc(g.note || "-")}</td><td>${g.users}</td><td>${g.services}</td>
    <td class="inline" style="flex-wrap:nowrap">
      <a href="javascript:;" class="lk" onclick="groupEditModal(${g.id})">编辑</a>
      <a href="javascript:;" class="lk g" onclick="groupAttachModal(${g.id},'${esc(g.name)}')">关联服务</a>
      <a href="javascript:;" class="lk r" onclick="groupDel(${g.id})">删除</a></td></tr>`).join("");
  document.getElementById("grpTable").innerHTML = (d.data.list || []).length ? `<table>
    <tr><th>分组编号</th><th>分组名称</th><th>分组描述</th><th>用户数</th><th>关联服务</th><th>操作</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无分组</p>`;
  groupOpts = ""; // 强制下次重新拉取
}
async function groupAddModal() {
  formModal("添加分组", `<div class="form-row"><label class="req">分组名称</label><input id="gName"></div>
    <div class="form-row"><label>分组描述</label><input id="gNote"></div>`, async () => {
    const r = await api("/group/addGroup", { body: { name: fv("gName"), note: fv("gNote") } });
    if (r.code !== 1) throw new Error(r.msg); toast("已创建"); enter("groups");
  });
}
async function groupEditModal(id) {
  const d = await api("/group/list");
  const g = (d.data.list || []).find(x => x.id === id);
  if (!g) return;
  formModal("编辑分组", `<div class="form-row"><label>分组名称</label><input id="gName" value="${esc(g.name)}"></div>
    <div class="form-row"><label>分组描述</label><input id="gNote" value="${esc(g.note)}"></div>`, async () => {
    const r = await api("/group/update", { body: { id, name: fv("gName"), note: fv("gNote") } });
    if (r.code !== 1) throw new Error(r.msg); toast("已更新"); enter("groups");
  });
}
async function groupAttachModal(gid, name) {
  const d = await api("/service/getServiceAndGroups");
  const cur = (d.data.attach?.[String(gid)]) || [];
  formModal("分组关联服务：" + esc(name), (d.data.services || []).map(s =>
    `<label style="display:block;margin:8px 0"><input type="checkbox" class="gSvc" value="${s.id}" ${cur.includes(s.id) ? "checked" : ""}> ${esc(s.name)}${s.port ? ` <span class="muted">(:${s.port})</span>` : ""}</label>`).join(""),
    async () => {
      const ids = [...document.querySelectorAll(".gSvc:checked")].map(x => +x.value);
      const r = await api("/service/submit", { body: { group_id: gid, service_ids: ids } });
      if (r.code !== 1) throw new Error(r.msg); toast("关联已保存"); enter("groups");
    });
}
function groupDel(id) {
  confirmModal("删除分组", "组内用户不会被删除，仅解除关联。确定？", async () => {
    const r = await api("/group/removeGroup?id=" + id, { body: {} });
    toast(r.msg, r.code === 1); enter("groups");
  });
}

/* ================= 服务管理 ================= */
async function pageServices(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">🖧 连接配置</h3>
      <div class="inline">
        <button class="primary" onclick="svcAddModal()">＋ 添加服务</button>
        <button class="ghost" onclick="enter('services')">⟳ 刷新</button>
      </div></div>
    <div id="svcTable">${loading}</div></div>`;
  const d = await api("/service/list");
  const list = d.data.list || [];
  document.getElementById("svcTable").innerHTML = list.length ? `<table>
    <tr><th>实例名</th><th>监听端口</th><th>虚拟网段</th><th>上限</th><th>在线</th><th>状态</th><th>操作</th></tr>
    ${list.map(s => `<tr>
      <td><b>${esc(s.name)}</b></td><td>${s.port}/${esc(s.proto)}</td><td>${esc(s.subnet)}</td>
      <td>${s.max_clients}</td><td>${s.online} 人</td>
      <td>${badge(s.status, "运行中", "已停止")}</td>
      <td class="inline" style="flex-wrap:nowrap">
        ${s.status ? `<a href="javascript:;" class="lk o" onclick="svcStop('${esc(s.name)}')">停止</a>`
                   : `<a href="javascript:;" class="lk g" onclick="svcStart('${esc(s.name)}')">启动</a>`}
        <a href="javascript:;" class="lk" onclick="svcEditModal('${esc(s.name)}')">编辑</a>
        <a href="javascript:;" class="lk g" onclick="svcConf('${esc(s.name)}')">配置</a>
        <a href="javascript:;" class="lk g" onclick="svcLog('${esc(s.name)}')">日志</a>
        <a href="javascript:;" class="lk r" onclick="svcDel(${s.id},'${esc(s.name)}')">删除</a></td></tr>`).join("")}</table>`
    : `<div class="tip-banner">ⓘ 提示：还没有服务，点击上面"添加服务"按钮创建一个服务吧!</div>`;
}
function svcAddModal() {
  formModal("添加服务", `
    <div class="form-row"><label class="req">实例名</label><input id="saName" placeholder="字母数字，如 office"></div>
    <div class="form-row"><label class="req">监听端口</label><input id="saPort" type="number" value="51194"></div>
    <div class="form-row"><label>协议</label><select id="saProto"><option>udp</option><option>tcp</option></select></div>
    <div class="form-row"><label>虚拟网段</label><div class="inline"><input id="saSubnet" value="10.8.0.0" style="width:130px"><input id="saMask" value="255.255.255.0" style="width:150px"></div></div>
    <div class="form-row"><label>推送路由</label><textarea id="saRoutes" placeholder="每行一条：192.168.1.0 255.255.255.0"></textarea></div>
    <div class="form-row inline"><label><input type="checkbox" id="saRGW"> <span><b>全局代理</b>：勾选 = 客户端全部流量与 DNS 都走 VPN；不勾选 = 只有下面推送的路由和「域名分流」走内网，其余（含 DNS 解析）走本地网络</span></label></div>
    <div class="form-row inline"><label><input type="checkbox" id="saC2C"> <span><b>允许客户端互访</b>(client-to-client)</span></label></div>`,
    async () => {
      const r = await api("/service/add", { body: {
        name: fv("saName"), port: +fv("saPort"), proto: fv("saProto"),
        subnet: fv("saSubnet"), mask: fv("saMask"), push_routes: fv("saRoutes"),
        redirect_gw: fc("saRGW"), client_to_client: fc("saC2C") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("实例已创建，正在启动"); enter("services");
    });
}
async function svcStart(name) { const r = await api("/service/start", { body: { name } }); toast(r.msg, r.code === 1); enter("services"); }
async function svcStop(name) { const r = await api("/service/stop", { body: { name } }); toast(r.msg, r.code === 1); enter("services"); }
async function svcEditModal(name) {
  const d = await api("/service/list");
  const s = (d.data.list || []).find(x => x.name === name);
  if (!s) return;
  formModal("编辑服务：" + esc(name), `
    <div class="tip-banner" style="margin-bottom:12px">ⓘ 端口修改后自动重载实例（在线用户会短暂断开）；对外映射端口与客户端 remote 需保持一致，改端口后请重新下发客户端配置。协议、虚拟网段创建后不可修改。</div>
    <div class="form-row"><label class="req">监听端口</label><input id="sePort" type="number" value="${s.port}"><span class="muted" style="flex:0 0 auto;white-space:nowrap">/${esc(s.proto)}</span></div>
    <div class="form-row"><label>推送路由</label><textarea id="seRoutes" placeholder="每行一条：192.168.1.0 255.255.255.0">${esc(s.push_routes || "")}</textarea></div>
    <div class="form-row inline"><label><input type="checkbox" id="seRGW" ${s.redirect_gw ? "checked" : ""}> <span><b>全局代理</b>：勾选 = 全部流量与 DNS 都走 VPN；不勾选 = 只有推送路由和域名分流走内网，其余走本地（不推送 DNS）</span></label></div>
    <div class="form-row inline"><label><input type="checkbox" id="seC2C" ${s.client_to_client ? "checked" : ""}> <span><b>允许客户端互访</b>(client-to-client)</span></label>
    <label style="margin-left:24px"><input type="checkbox" id="seDupCN" ${s.duplicate_cn ? "checked" : ""}> <span><b>允许重复登录</b>(duplicate-cn)</span></label></div>
    <div class="form-row"><label>最大客户端数</label><input id="seMax" type="number" value="${s.max_clients}"></div>`,
    async () => {
      const r = await api("/service/editService", { body: { id: s.id, port: +fv("sePort"), max_clients: +fv("seMax"),
        push_routes: fv("seRoutes"), redirect_gw: fc("seRGW"),
        client_to_client: fc("seC2C"), duplicate_cn: fc("seDupCN") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("已更新并重载实例"); enter("services");
    });
}
async function svcConf(name) {
  const r = await api("/service/getServiceConfiguration", { body: { name } });
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mConf" onclick="if(event.target===this)closeModal('mConf')"><div class="modal" style="width:760px">
    <h3>${esc(name)} · server.conf</h3><pre class="log">${esc(r.data.conf)}</pre>
    <div class="actions"><button class="primary" onclick="closeModal('mConf')">关 闭</button></div></div></div>`);
}
async function svcLog(name) {
  const r = await api("/log/vpnserverlog?service=" + encodeURIComponent(name));
  $app.insertAdjacentHTML("beforeend", `<div class="modal-mask" id="mLog" onclick="if(event.target===this)closeModal('mLog')"><div class="modal" style="width:800px">
    <h3>${esc(name)} · 运行日志</h3><pre class="log">${esc(r.data.log || "(暂无日志)")}</pre>
    <div class="actions"><button class="primary" onclick="closeModal('mLog')">关 闭</button></div></div></div>`);
}
function svcDel(id, name) {
  confirmModal("删除服务", `将停止并删除实例 <b>${esc(name)}</b> 及其证书，该实例下用户配置将失效。确定？`, async () => {
    const r = await api("/service/removeService", { body: { id } });
    toast(r.msg, r.code === 1); enter("services");
  });
}

/* ================= 备份恢复 ================= */
async function pageBackup(main) {
  main.innerHTML = `<div class="card">
    <h3>💾 数据备份与恢复 <span class="hint">更推荐使用手动备份更加稳妥</span></h3>
    <div class="inline" style="align-items:flex-start;gap:40px">
      <div style="text-align:center">
        <div style="font-size:44px">🗄</div>
        <div class="inline"><button class="primary" onclick="doBackup()">备份数据</button></div>
      </div>
      <div style="text-align:center">
        <div style="font-size:44px">🗃</div>
        <div class="inline"><button class="ghost" onclick="document.getElementById('bkFile').click()">上传备份文件</button>
          <input type="file" id="bkFile" accept=".tar.gz" style="display:none" onchange="backupUpload(this)"></div>
      </div>
    </div>
    <div class="muted" style="font-size:12px;line-height:1.7;margin:10px 0 0">
      ⓘ 上传仅把 <code>.tar.gz</code> 备份存入服务器备份目录并登记到下方列表，<b>不会自动恢复数据</b>；
      恢复需手动解压覆盖数据目录后重启容器。删除备份会同时移除磁盘文件，不可恢复。
    </div>
    <h3 style="margin-top:22px">备份列表</h3>
    <div id="bkList">${loading}</div></div>`;
  backupList();
}
async function doBackup() {
  const r = await api("/system/backup");
  toast(r.msg + " " + (r.data?.filename || ""), r.code === 1);
  backupList();
}
async function backupList() {
  const el = document.getElementById("bkList");
  if (!el) return;
  try {
    const r = await api("/system/getBackupInfo");
    const list = r.data.list || [];
    el.innerHTML = list.length ? `<table><tr><th>文件</th><th>大小</th><th>时间</th><th style="width:140px">操作</th></tr>
      ${list.map(b => `<tr><td>${esc(b.filename)}</td><td>${(b.size / 1024).toFixed(1)} KB</td><td>${esc(b.created_at)}</td>
        <td><a href="javascript:;" class="lk" data-fn="${esc(b.filename)}" onclick="backupDownload(this.dataset.fn)">⬇ 下载</a>
        <a href="javascript:;" class="lk r" data-fn="${esc(b.filename)}" onclick="backupDelete(this.dataset.fn)">🗑 删除</a></td></tr>`).join("")}</table>`
      : `<p class="muted">提示：暂无备份文件。</p>`;
  } catch (e) { el.innerHTML = errBox(e.message); }
}
async function backupDownload(fn) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(API_BASE + "/system/downloadBackupFile", {
      method: "POST", headers, credentials: "include", body: JSON.stringify({ filename: fn }) });
    const ct = res.headers.get("Content-Type") || "";
    if (ct.includes("json")) { const d = await res.json(); throw new Error(d.msg || "下载失败"); }
    if (!res.ok) throw new Error("HTTP " + res.status);
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url; a.download = fn;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { toast("下载失败：" + e.message, false); }
}
async function backupDelete(fn) {
  if (!confirm("确定删除备份 " + fn + " 吗？\n磁盘文件会一并移除，此操作不可恢复。")) return;
  const r = await api("/system/deleteBackupFile", { body: { filename: fn } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) backupList();
}
async function backupUpload(input) {
  const f = input.files && input.files[0];
  if (!f) return;
  if (!f.name.endsWith(".tar.gz")) { toast("仅支持 .tar.gz 备份文件", false); input.value = ""; return; }
  const fd = new FormData(); fd.append("file", f);
  try {
    const r = await apiUpload("/system/submitUpload", fd);
    toast(r.msg, r.code === 1);
    if (r.code === 1) backupList();
  } catch (e) { toast("上传失败：" + e.message, false); }
  input.value = "";
}

/* ================= 客户端下载 ================= */
async function pageClientDownload(main) {
  main.innerHTML = `<div class="card" style="max-width:900px">
    <h3>⬇ 客户端下载 <span class="hint">开关、可见范围与安装包管理</span></h3>
    <div class="tip-banner">ⓘ 开启后 <code>/downloads</code> 才显示下载按钮；关闭后页面只提示「暂未开放」，直接访问下载链接同样返回 403。默认「仅管理员登录后下载」，如需全员免登录分发请切换为「公开」。</div>
    <div class="form-row"><label>开放下载</label><select id="cdEnabled" style="max-width:260px">
      <option value="1">开启（显示下载按钮）</option>
      <option value="0">关闭（隐藏下载按钮）</option></select></div>
    <div class="form-row"><label>可见范围</label><select id="cdScope" style="max-width:260px">
      <option value="admin">仅管理员登录后下载</option>
      <option value="public">免登录公开下载</option></select></div>
    <div class="form-row"><label></label>
      <button class="primary" onclick="clientDlSave()">✓ 保存设置</button>
      <button class="ghost" onclick="window.open('/downloads','_blank')">↗ 打开下载页</button></div>
    <div class="muted" style="font-size:12px">下载页地址：<code>/downloads</code>（同源，自动携带登录 cookie）</div>
    <div class="muted" style="font-size:12px;margin-top:4px">ⓘ 终端用户打开下载页时会<b>按访问设备自动筛选</b>：Windows 只看到 Windows 安装包与网关脚本，macOS 只看到 macOS 安装包，其它平台可手动切换。此处管理列表始终显示全部文件。</div>
  </div>
  <div class="card" style="max-width:900px">
    <h3>✉ 账号邮件附件 <span class="hint">用户账号页「邮件」按钮（含批量发送）附带的内容</span></h3>
    <div class="form-row"><label>附带客户端</label><select id="cdAttachMail" style="max-width:260px">
      <option value="0">关闭（只发配置文件）</option>
      <option value="1">开启（按下方勾选附带客户端安装包）</option></select></div>
    <div class="form-row"><label></label><span class="muted" style="font-size:12px">开启后可选择邮件内容；客户端发送可以不带配置文件。默认关闭。</span></div>
    <div class="form-row"><label>邮件内容</label>
      <label style="width:auto;text-align:left"><input type="checkbox" id="cdAttachCfg"> VPN 配置文件（<code>用户名_实例.tgz</code>）</label></div>
    <div class="form-row"><label></label>
      <label style="width:auto;text-align:left"><input type="checkbox" id="cdAttachWin"> Windows 客户端安装包（自动取最新版）</label></div>
    <div class="form-row"><label></label>
      <label style="width:auto;text-align:left"><input type="checkbox" id="cdAttachMac"> macOS 客户端安装包（自动取最新版）</label></div>
    <div class="muted" style="font-size:12px">ⓘ 需先在「系统设置 → 邮件服务」配置 SMTP；exe + pkg 合计约 8MB，在常见邮箱 25MB 附件限内。</div>
  </div>
  <div class="card" style="max-width:900px">
    <h3>📦 单独上传安装包</h3>
    <div class="form-row"><label>Windows</label>
      <input type="file" id="cdFileWin" accept=".exe,.msi" style="max-width:320px">
      <button class="ghost" onclick="clientDlUpload('windows')">上传</button></div>
    <div class="form-row"><label>macOS</label>
      <input type="file" id="cdFileMac" accept=".pkg,.dmg,.zip" style="max-width:320px">
      <button class="ghost" onclick="clientDlUpload('macos')">上传</button></div>
    <div class="muted" style="font-size:12px;line-height:1.7;margin-top:8px">
      ⓘ <b>可覆盖、可删除</b>：上传文件与已有文件<b>同名</b>时直接覆盖；<b>不同名</b>时自动删除该平台的旧上传包，始终只保留一个。
      列表里点「🗑 删除」可随时移除上传包，移除后自动恢复显示镜像内置的同平台包（内置包本身不可删，也不会丢失）。
      只替换对应平台，另一平台不受影响。单个文件上限 300MB，文件存在数据卷中，重建容器不丢失。<br>
      <code>configure-gateway.ps1</code> 由服务器按「全局设置 → 公网地址」自动生成（域名与端口自动跟随），无需上传。<br>
      <b>卸载工具</b>：<code>KSVPN-Windows-Uninstall.zip</code> / <code>KSVPN-macOS-Uninstall.zip</code> 标有「🔒 仅管理员」，
      普通用户在下载页看不到、直链也会被拦截；需要时点该行「✉ 发送」输入邮箱发给个人，
      邮件会自动附上卸载脚本<b>与完整卸载教程</b>。
    </div>
  </div>
  <div class="card" style="max-width:900px">
    <h3>当前可下载文件 <span class="hint" id="cdCount"></span></h3>
    <div id="cdList">${loading}</div></div>`;
  await clientDlLoad();
}
async function clientDlLoad() {
  const r = await api("/system/clientDownload/get");
  if (r.code !== 1) throw new Error(r.msg || "读取客户端下载设置失败");
  const d = r.data || {};
  const en = document.getElementById("cdEnabled");
  const sc = document.getElementById("cdScope");
  const am = document.getElementById("cdAttachMail");
  if (en) en.value = d.enabled === false ? "0" : "1";
  if (sc) sc.value = d.scope === "public" ? "public" : "admin";
  if (am) am.value = d.attach_mail ? "1" : "0";
  const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v !== false; };
  setChk("cdAttachCfg", d.attach_cfg);
  setChk("cdAttachWin", d.attach_win);
  setChk("cdAttachMac", d.attach_mac);
  const list = d.files || [];
  const cnt = document.getElementById("cdCount");
  if (cnt) cnt.textContent = `共 ${list.length} 个 · ${d.enabled === false ? "下载已关闭" : (d.scope === "public" ? "公开可见" : "仅管理员可见")}`;
  const el = document.getElementById("cdList");
  if (!el) return;
  el.innerHTML = list.length ? `<table><tr><th>平台</th><th>文件</th><th>大小</th><th>说明</th><th>来源</th><th style="width:150px">操作</th></tr>
    ${list.map(f => `<tr><td>${esc(f.Platform)}</td><td>${esc(f.Name)}</td><td>${esc(f.Size)}</td>
      <td class="muted">${esc(f.Desc)}</td><td>${f.Source === "custom" ? '<span class="badge ok">上传</span>' : '<span class="badge off">内置</span>'}${f.admin_only ? ' <span class="badge" title="普通用户在下载页看不到，直链也会被拦截；可点右侧「发送」把文件与教程发到个人邮箱">🔒 仅管理员</span>' : ''}</td>
      <td>${f.Source === "custom" ? `<a href="javascript:;" class="lk r" data-fn="${esc(f.Name)}" onclick="clientDlDelete(this.dataset.fn)">🗑 删除</a> ` : ""}
      <a href="javascript:;" class="lk" data-fn="${esc(f.Name)}" onclick="clientDlMail(this.dataset.fn)">✉ 发送</a></td></tr>`).join("")}</table>`
    : `<p class="muted">暂无安装包，请在上方上传。</p>`;
}
async function clientDlSave() {
  const r = await api("/system/clientDownload/save", { body: {
    enabled: fv("cdEnabled") === "1", scope: fv("cdScope"),
    attach_mail: fv("cdAttachMail") === "1",
    attach_cfg: document.getElementById("cdAttachCfg").checked,
    attach_win: document.getElementById("cdAttachWin").checked,
    attach_mac: document.getElementById("cdAttachMac").checked } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) clientDlLoad();
}
async function clientDlUpload(platform) {
  const inp = document.getElementById(platform === "windows" ? "cdFileWin" : "cdFileMac");
  const f = inp.files && inp.files[0];
  if (!f) return toast("请先选择安装包", false);
  toast("正在上传 " + f.name + " …");
  const fd = new FormData();
  fd.append("platform", platform);
  fd.append("file", f);
  try {
    const r = await apiUpload("/system/clientDownload/upload", fd);
    toast(r.msg, r.code === 1);
    if (r.code === 1) { inp.value = ""; await clientDlLoad(); }
  } catch (e) { toast("上传失败：" + e.message, false); }
}
async function clientDlDelete(fn) {
  if (!confirm("确定删除上传的安装包 " + fn + " 吗？\n删除后会自动恢复显示镜像内置的同平台包。")) return;
  const r = await api("/system/clientDownload/delete", { body: { filename: fn } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) clientDlLoad();
}
// 把安装包以附件发送到用户邮箱（需先在「邮件服务」配置 SMTP）
async function clientDlMail(fn) {
  const email = prompt("发送「" + fn + "」到用户邮箱：", "");
  if (email === null) return;
  if (!email.trim()) return toast("请输入邮箱地址", false);
  toast("正在发送 " + fn + " 到 " + email.trim() + " …");
  try {
    const r = await api("/system/clientDownload/mail", { body: { filename: fn, email: email.trim() } });
    toast(r.msg, r.code === 1);
  } catch (e) { toast("发送失败：" + e.message, false); }
}

/* ================= SMTP 配置 ================= */
async function pageSmtp(main) {
  const [smtp, tpl] = await Promise.all([
    api("/system/getSmtpInfo").catch(() => ({ data: {} })),
    api("/system/getMailTemplate").catch(() => ({ data: {} })),
  ]);
  const s = smtp.data || {};
  const t = tpl.data || {};
  main.innerHTML = `<div class="card wide">
    <h3>✉ 邮件服务</h3>
    <div class="form-row"><label>SMTP服务器</label><input id="smHost" value="${esc(s.host || "")}" placeholder="smtp.example.com"></div>
    <div class="form-row"><label>SMTP用户</label><input id="smUser" value="${esc(s.user || "")}"></div>
    <div class="form-row"><label>SMTP用户秘钥</label><input id="smPass" type="password" value="${esc(s.pass || "")}"></div>
    <div class="form-row"><label>SMTP服务端口</label><input id="smPort" type="number" value="${s.port || 465}" style="max-width:120px"></div>
    <div class="form-row"><label>发送者标题</label><input id="smTitle" value="${esc(s.title || "")}" placeholder="如：KSVPN（收件人看到的发件人名称）"></div>
    <div class="form-row"><label>发件人地址</label><input id="smSender" value="${esc(s.sender || "")}" placeholder="必须是邮箱，如 421381118@qq.com"></div>
    <div class="form-row"><label></label><label style="width:auto;text-align:left"><input type="checkbox" id="smSSL" ${s.ssl ? "checked" : ""}> SSL(465)</label></div>
    <div class="form-row"><label></label><div class="inline">
      <button class="primary" onclick="smtpSave()">✓ 更新</button>
      <button class="orange" onclick="smtpTest()">➤ 发送测试邮件</button></div></div>
  </div>
  <div class="card wide">
    <h3>📝 邮件模板编辑 <span class="hint">发送账号信息给用户时使用 · 本地账号与域账号模板相互独立</span></h3>
    <div class="form-row"><label style="font-weight:500">▼ 本地账号模板</label><span class="muted" style="font-size:12px">发给认证类型为本地密码/TOTP 的用户</span></div>
    <div class="form-row"><label>邮件主题</label><input id="mtSubject" value="${esc(t.subject || "")}"></div>
    <div class="form-row" style="align-items:flex-start"><label>邮件正文</label>
      <textarea id="mtBody" style="min-height:200px;font-family:monospace;font-size:13px">${esc(t.body || "")}</textarea></div>
    <div class="form-row"><label style="font-weight:500">▼ LDAP 域账号模板</label><span class="muted" style="font-size:12px">发给认证类型为 LDAP 的用户 · 两栏都留空则使用内置 LDAP 默认模板</span></div>
    <div class="form-row"><label>邮件主题</label><input id="mtSubjectLdap" value="${esc(t.subject_ldap || "")}" placeholder="留空使用 LDAP 默认模板主题"></div>
    <div class="form-row" style="align-items:flex-start"><label>邮件正文</label>
      <textarea id="mtBodyLdap" style="min-height:200px;font-family:monospace;font-size:13px" placeholder="留空使用 LDAP 默认模板正文">${esc(t.body_ldap || "")}</textarea></div>
    <div class="form-row"><label></label>
      <div class="tip-banner" style="margin:0">ⓘ 可用占位符：<code>{username}</code> 用户名 · <code>{password}</code> 密码 · <code>{expire}</code> 到期时间 · <code>{download_url}</code> 客户端下载地址 · <code>{sys_name}</code> 系统名称 · <code>{auth_note}</code> 使用说明。<br>
      说明：<code>{password}</code> 对 LDAP 账号会自动显示“LDAP 统一认证（使用域账号密码）”，不会出现密码 “-”；邮件会自动附带该用户的 VPN 配置文件（<code>用户名_实例.tgz</code>）。正文支持 HTML，本地模板留空保存即恢复默认模板，LDAP 模板留空保存即使用 LDAP 默认模板（不再回落本地）。</div></div>
    <div class="form-row"><label></label><div class="inline">
      <button class="primary" onclick="mailTplSave()">✓ 保存模板</button>
      <button class="orange" onclick="mailTplReset()">⟲ 恢复默认</button></div></div>
  </div>`;
}
async function mailTplSave() {
  const r = await api("/system/updateMailTemplate", { body: { subject: fv("mtSubject"), body: fv("mtBody"),
    subject_ldap: fv("mtSubjectLdap"), body_ldap: fv("mtBodyLdap") } });
  toast(r.msg, r.code === 1);
}
async function mailTplReset() {
  document.getElementById("mtSubject").value = "";
  document.getElementById("mtBody").value = "";
  document.getElementById("mtSubjectLdap").value = "";
  document.getElementById("mtBodyLdap").value = "";
  const r = await api("/system/updateMailTemplate", { body: { subject: "", body: "", subject_ldap: "", body_ldap: "" } });
  toast("已恢复默认模板", r.code === 1);
  enter("smtp");
}
async function smtpSave() {
  const r = await api("/system/updateEmail", { body: { host: fv("smHost"), port: +fv("smPort"),
    user: fv("smUser"), pass: fv("smPass"), title: fv("smTitle"), sender: fv("smSender"),
    ssl: !!document.getElementById("smSSL")?.checked } });
  toast(r.msg, r.code === 1);
}
async function smtpTest() {
  const e = prompt("测试收件邮箱：", "421381118@qq.com"); if (!e) return;
  toast("发送中…");
  const r = await api("/system/sendTestMail", { body: { email: e } });
  toast(r.msg, r.code === 1);
}

/* ================= SSL 证书配置 ================= */
async function pageCert(main) {
  let t = {};
  try { const r = await api("/system/getKeyFile"); t = r.data || {}; } catch (e) {}
  const hasCustom = !!(t.cert && t.cert.includes("BEGIN CERTIFICATE"));
  const infoHtml = hasCustom
    ? `当前证书：<b>${esc(t.subject || "-")}</b> · 有效期至 <b>${esc(t.not_after || "-")}</b>`
    : "当前使用内置自签证书，浏览器会有不受信任提示，可在此粘贴正式证书。";
  main.innerHTML = `<div class="card wide">
    <h3>🔒 证书管理</h3>
    <div class="tip-banner" style="margin-bottom:14px">ⓘ 粘贴 PEM 格式的 <b>.crt 证书</b>与 <b>.key 私钥</b>内容，点击「更新证书配置」后<b>立即生效，无需重启服务</b>。<br>${infoHtml}</div>
    <div style="display:flex;gap:18px;flex-wrap:wrap">
      <div style="flex:1;min-width:300px">
        <div class="cert-tools"><b>证书内容</b><span class="muted" style="font-size:12px">.crt / 含中间证书链</span>
          <span class="spacer"></span>
          <a href="javascript:;" class="lk" onclick="document.getElementById('cfCert').value=''">⌫ 清空</a>
          <a href="javascript:;" class="lk" onclick="certDownload('crt')">⬇ 下载 .crt</a></div>
        <textarea id="cfCert" style="min-height:280px;font-family:monospace;font-size:12px;width:100%" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----">${esc(t.cert || "")}</textarea>
      </div>
      <div style="flex:1;min-width:300px">
        <div class="cert-tools"><b>私钥内容</b><span class="muted" style="font-size:12px">.key / 请妥善保管</span>
          <span class="spacer"></span>
          <a href="javascript:;" class="lk" onclick="document.getElementById('cfKey').value=''">⌫ 清空</a>
          <a href="javascript:;" class="lk" onclick="certDownload('key')">⬇ 下载 .key</a></div>
        <textarea id="cfKey" style="min-height:280px;font-family:monospace;font-size:12px;width:100%" placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----">${esc(t.key || "")}</textarea>
      </div>
    </div>
    <div class="form-row" style="margin-top:14px"><label></label>
      <div class="inline" style="flex-wrap:wrap;gap:10px">
        <button class="primary" onclick="certSave()">✓ 更新证书配置</button>
        <button class="ghost" onclick="certDownload('both')">⬇ 下载合并 PEM（证书+私钥）</button>
        <span class="muted" style="font-size:12px">保存前会自动校验证书与私钥是否配对，配对错误不会落盘。</span></div></div>
    <div class="muted" style="font-size:12px;line-height:1.8;margin-top:4px">
      ⓘ 下载或复制的两个 PEM 文件可直接用于 Nginx、Apache、HAProxy 等 HTTPS 服务，前提是<b>访问域名与证书匹配</b>；
      证书链为 ECDSA（私钥 <code>EC PRIVATE KEY</code>），目标服务需支持 EC 证书。Let's Encrypt 证书 90 天有效，
      <b>自动续签只更新本服务器</b>，复制到其它机器后需在续签后重新导出。
    </div>
  </div>`;
  // 自动续签面板（独立请求，失败不影响上面的手工上传区）
  main.insertAdjacentHTML("beforeend", `<div class="card wide" id="certAutoCard" style="margin-top:16px"><h3>🔄 证书自动续签</h3><div class="muted" style="padding:10px 0">加载中…</div></div>`);
  renderCertAuto();
}

async function renderCertAuto() {
  const box = document.getElementById("certAutoCard");
  if (!box) return;
  let d = {};
  try { d = (await api("/cert/auto/get")).data || {}; } catch (e) { }
  const st = d.status || {};
  const days = st.days_left;
  const stColor = days === undefined || days > 15 ? "ok" : (days > 7 ? "warn" : "danger");
  const stText = days === undefined || days === null ? "未知"
    : (days < 0 ? `已过期 ${-days} 天` : `剩余 ${days} 天`);
  const badgeCls = st.source === "acme" ? "ok" : (st.source === "upload" ? "blue" : "gray");
  const running = !!st.running;
  const opt = (v, t, cur) => `<option value="${v}" ${cur === v ? "selected" : ""}>${t}</option>`;
  box.innerHTML = `<div class="topbar" style="margin-bottom:8px">
      <h3 style="margin:0">🔄 证书自动续签</h3>
      <div class="inline">
        <button class="ghost small" onclick="renderCertAuto()">⟳ 刷新状态</button>
        <button class="ghost small" onclick="certAutoTest()">⚡ 测试 DNS 凭证</button>
        <button class="primary small" onclick="certAutoSave()">✓ 保存配置</button>
        <button class="primary small" onclick="certAutoIssue()" ${running ? "disabled" : ""}>${running ? "签发中…" : "⚡ 立即签发"}</button>
      </div></div>
    <div class="tip-banner" style="margin-bottom:12px">
      ⓘ 用 <b>Let's Encrypt</b> 免费证书配合云 DNS 的 <b>DNS-01</b> 验证自动签发，到期前 <b>${d.days || 30} 天</b>自动续签并热加载，
      无需重启服务。域名的 NS 必须托管在所选云厂商；凭证只用于增删 <code>_acme-challenge</code> TXT 记录，建议用<b>子账号</b>并只授权 DNS 权限。
    </div>
    <div class="form-row"><label>当前证书</label>
      <div class="inline" style="align-items:center;gap:10px">
        <span class="badge ${badgeCls}">${esc(d.source_name || "-")}</span>
        <span>${esc(st.subject || "-")}</span>
        <span class="muted">有效期至 ${esc(st.not_after || "-")}</span>
        <span class="badge ${stColor === "ok" ? "ok" : (stColor === "warn" ? "blue" : "off")}">${stText}</span>
      </div></div>
    <div class="form-row inline"><label style="width:auto"><input type="checkbox" id="caEnabled" ${d.enabled ? "checked" : ""}> <b>启用自动续签</b>（到期前自动换新证书）</label></div>
    <div class="form-row"><label class="req">域名</label><input id="caDomains" value="${esc(d.domains || "")}" placeholder="vpn.example.com,www.example.com（多个用逗号分隔，支持泛域名 *.example.com）"></div>
    <div class="form-row"><label class="req">注册邮箱</label><input id="caEmail" value="${esc(d.email || "")}" placeholder="用于 Let's Encrypt 到期通知"></div>
    <div class="form-row"><label>DNS 服务商</label><select id="caProvider">
      ${opt("aliyun", "阿里云 DNS", d.provider)}${opt("tencent", "腾讯云 DNSPod", d.provider)}</select></div>
    <div class="form-row"><label class="req">AccessKey / SecretId</label><input id="caAK" value="${esc(d.access_key || "")}" placeholder="${d.has_key ? "已保存，留空或保持打码表示不修改" : "阿里云 AccessKeyId / 腾讯云 SecretId"}"></div>
    <div class="form-row"><label class="req">SecretKey</label><input id="caSK" type="password" value="${esc(d.secret_key || "")}" placeholder="${d.has_key ? "已保存，留空表示不修改" : "阿里云 AccessKeySecret / 腾讯云 SecretKey"}"></div>
    <div class="form-row"><label>提前天数</label><input id="caDays" type="number" value="${d.days || 30}" min="7" max="90">
      <span class="muted" style="flex:0 0 auto;white-space:nowrap">天（LE 证书 90 天，建议 30）</span></div>
    <div class="form-row inline"><label><input type="checkbox" id="caStaging" ${d.staging ? "checked" : ""}> 使用 LE <b>测试环境</b>（调试用，签出的证书浏览器不信任、不计入正式配额）</label></div>
    <div class="form-row"><label>最近结果</label>
      <div class="muted" style="flex:1">${esc(st.message || "尚无记录")}${st.last_at ? `<br><span style="font-size:12px">${esc(st.last_at)}</span>` : ""}</div></div>`;
}

async function certAutoSave() {
  const r = await api("/cert/auto/save", { body: {
    enabled: !!document.getElementById("caEnabled").checked,
    domains: fv("caDomains"), email: fv("caEmail"), provider: fv("caProvider"),
    access_key: fv("caAK"), secret_key: fv("caSK"),
    days: +fv("caDays"), staging: !!document.getElementById("caStaging").checked } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) renderCertAuto();
}

async function certAutoTest() {
  toast("正在写入测试 TXT 记录…");
  const r = await api("/cert/auto/test", { body: {
    domains: fv("caDomains"), provider: fv("caProvider"),
    access_key: fv("caAK"), secret_key: fv("caSK") } });
  toast(r.msg, r.code === 1);
}

async function certAutoIssue() {
  const r = await api("/cert/auto/issue", { body: {
    domains: fv("caDomains"), email: fv("caEmail"), provider: fv("caProvider"),
    access_key: fv("caAK"), secret_key: fv("caSK"),
    days: +fv("caDays"), staging: !!document.getElementById("caStaging").checked } });
  if (r.code !== 1) return toast(r.msg, false);
  toast("已开始签发，约 1-3 分钟");
  // 轮询状态，成功后刷新页面信息
  let n = 0;
  const timer = setInterval(async () => {
    n++;
    const s = await api("/cert/auto/status");
    const stt = (s.data || {}).status || {};
    if (!stt.running || n > 60) {
      clearInterval(timer);
      toast(stt.running ? "仍在签发，请稍后刷新" : (stt.last_ok ? "证书已签发并生效" : (stt.message || "签发结束，请查看结果")), !stt.running && !stt.last_ok ? false : true);
      renderCertAuto();
    }
  }, 5000);
}
/* 证书导出：纯前端把文本框内容存成 PEM 文件，不经过后端 */
function downloadText(name, text) {
  const v = (text || "").trim();
  if (!v) return toast("内容为空，无可下载内容", false);
  const blob = new Blob([v + "\n"], { type: "application/x-pem-file;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("已下载 " + name);
}
function certDownload(kind) {
  const cert = (document.getElementById("cfCert")?.value || "").trim();
  const key = (document.getElementById("cfKey")?.value || "").trim();
  if (kind === "crt") return downloadText("sslvpn-server.crt", cert);
  if (kind === "key") return downloadText("sslvpn-server.key", key);
  if (!cert || !key) return toast("证书或私钥内容为空", false);
  downloadText("sslvpn-server-bundle.pem", cert + "\n" + key + "\n");
}
async function certSave() {
  const cert = document.getElementById("cfCert").value.trim();
  const key = document.getElementById("cfKey").value.trim();
  if (!cert || !key) return toast("请粘贴证书与私钥内容", false);
  const r = await api("/system/updateKeyFile", { body: { cert, key } });
  toast(r.msg, r.code === 1);
  if (r.code === 1) enter("cert");
}

/* ================= 扫码登录（飞书 / 钉钉 / 企业微信） ================= */
let ssoTab = "feishu";
async function pageFeishu(main) {
  let d = {};
  try { d = (await api("/system/getFeishu")).data || {}; } catch (e) { }
  const P = {};
  (d.providers || []).forEach(p => { P[p.key] = p; });
  const f = P.feishu || {}, dt = P.dingtalk || {}, wc = P.wecom || {};
  const ph = (d.public_host || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const base = d.base_url || (ph ? `https://${ph}/feishu-sso` : "https://" + location.host + "/feishu-sso");
  const configured = d.base_url_configured || "";  // 管理员显式填过的值；留空 = 跟随全局
  const derived = d.base_url_derived || base;      // 跟随全局时会自动变成的地址
  const def = d.default_provider || "feishu";
  const opt = (v, t, cur) => `<option value="${v}" ${cur === v ? "selected" : ""}>${t}</option>`;
  const onoff = (id, v) => `<select id="${id}">${opt("1", "启用", v ? "1" : "0")}${opt("0", "停用", v ? "1" : "0")}</select>`;
  const mockSel = (id, v) => `<select id="${id}">${opt("0", "关闭（正式对接）", v ? "1" : "0")}${opt("1", "开启（不调第三方接口）", v ? "1" : "0")}</select>`;

  main.innerHTML = `<div class="card wide">
    <div class="topbar"><h3 style="margin:0">🪪 扫码登录</h3>
      <div class="inline">
        <button class="ghost small" onclick="enter('sso')">⟳ 刷新</button>
        <button class="ghost small" onclick="ssoTestDoc()">⚡ 测试当前渠道凭证</button>
        <button class="primary small" onclick="ssoSave()">✓ 保存全部</button>
      </div></div>
    <div class="tip-banner" style="margin-bottom:14px">
      ⓘ 客户端可用<b>飞书 / 钉钉 / 企业微信扫码</b>代替输入密码：扫码确认 → 系统把身份映射为 VPN 账号 → 下发一次性口令
      <code>FS1.xxxx</code> 作为 OpenVPN 密码 → <b>用一次即失效</b>（默认 60 秒）。三个渠道可同时启用，客户端通过
      <code>provider</code> 参数选择；不传则用下面的「默认渠道」。<br>
      当前已启用：<b>${(d.enabled_count || 0) ? (d.providers || []).filter(p => p.enabled).map(p => p.name).join("、") : "无"}</b>
      　回调地址：<code>${esc(base)}/callback</code>（${configured ? "<b>自定义基地址</b>，不再跟随全局" : "跟随「全局设置 → 服务器公网地址」，<b>域名与端口自动联动</b>"}）
    </div>

    <div style="display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end">
      <div style="flex:1;min-width:240px">
        <div class="form-row"><label>默认渠道</label><select id="ssoDefault">
          ${opt("feishu", "飞书", def)}${opt("dingtalk", "钉钉", def)}${opt("wecom", "企业微信", def)}</select></div>
      </div>
      <div style="flex:1.4;min-width:280px">
        <div class="form-row"><label>回调基地址</label><input id="ssoBase" value="${esc(configured)}" placeholder="留空 = 跟随全局公网地址（含端口）" onblur="autoHttps(this)"><button class="ghost small" type="button" style="flex:0 0 auto;margin-left:8px" onclick="ssoFollowGlobal()" title="清空并恢复跟随全局公网地址">↺ 跟随全局</button></div>
        <div class="muted" style="font-size:12px;margin-top:-8px;margin-bottom:12px">留空时飞书 / 钉钉 / 企业微信三个渠道的回调地址随「全局设置 → 服务器公网地址」自动更新，包含端口；当前自动推导：<code>${esc(derived)}</code>。建议把全局公网地址写成 <code>https://域名:58443</code>（带端口），回调就不依赖当前访问地址；改动后要到各开放平台同步修改重定向 URL。</div>
      </div>
      <div style="flex:1;min-width:200px">
        <div class="form-row"><label>全局联调模式</label>${mockSel("ssoMockAll", d.mock_all === 1)}</div>
      </div>
    </div>
    <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:6px">
      <div style="flex:1;min-width:200px"><div class="form-row"><label>授权有效期（秒）</label><input id="ssoTtl" type="number" min="60" max="1800" value="${d.device_ttl || 300}"></div></div>
      <div style="flex:1;min-width:200px"><div class="form-row"><label>口令有效期（秒）</label><input id="ssoTok" type="number" min="10" max="600" value="${d.token_ttl || 60}"></div></div>
      <div style="flex:1.4;min-width:260px"><div class="form-row"><label>服务校验密钥</label><input id="ssoSecret" type="password" placeholder="${d.verify_secret_set ? "已设置（留空不修改）" : "选填 ≥32 位，仅供旧脚本调 /token/verify"}"></div></div>
    </div>

    <div class="inline" style="gap:6px;margin:16px 0 10px;border-bottom:1px solid var(--line);padding-bottom:0">
      <a href="javascript:;" class="lk sso-tab" data-ssotab="feishu" onclick="ssoSwitchTab('feishu')">飞书${f.enabled ? ' <span class="badge ok" style="font-size:11px">启用</span>' : ""}</a>
      <a href="javascript:;" class="lk sso-tab" data-ssotab="dingtalk" onclick="ssoSwitchTab('dingtalk')">钉钉${dt.enabled ? ' <span class="badge ok" style="font-size:11px">启用</span>' : ""}</a>
      <a href="javascript:;" class="lk sso-tab" data-ssotab="wecom" onclick="ssoSwitchTab('wecom')">企业微信${wc.enabled ? ' <span class="badge ok" style="font-size:11px">启用</span>' : ""}</a>
    </div>

    <div data-ssopanel="feishu" style="display:none">
      <div class="tip-banner">在 <b>open.feishu.cn</b> 创建「企业自建应用」→ 凭证与基础信息取 App ID / App Secret；<br>
        权限需勾选 <code>contact:user.email:readonly</code>（读企业邮箱）；「安全设置 → 重定向 URL」填 <code>${esc(base)}/callback</code>。</div>
      <div style="display:flex;gap:18px;flex-wrap:wrap">
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>启用</label>${onoff("fsOn", f.enabled === 1)}</div>
          <div class="form-row"><label class="req">App ID</label><input id="fsId" value="${esc(f.app_id || "")}" placeholder="cli_xxxxxxxxxxxxxxxx"></div>
          <div class="form-row"><label>App Secret</label><input id="fsSec" type="password" placeholder="${f.secret_set ? "已保存，留空不修改" : "凭证与基础信息 → App Secret"}"></div>
          <div class="form-row"><label>租户 Key</label><input id="fsTenant" value="${esc(f.tenant_key || "")}" placeholder="选填；填写后只接受该租户账号"></div>
        </div>
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>邮箱域名白名单</label><input id="fsDomain" value="${esc(f.email_domain || "")}" placeholder="qq.com（逗号分隔，留空不限制）"></div>
          <div class="form-row"><label>飞书ID匹配属性</label><input id="fsAttr" value="${esc(f.match_attr || "carLicense")}" placeholder="carLicense"></div>
          <div class="form-row"><label>联调模式</label>${mockSel("fsMock", f.mock === 1)}</div>
        </div>
      </div>
      <details style="margin-top:4px"><summary style="cursor:pointer;color:var(--primary);font-size:13px">高级：接口地址 / Scope / Token 模式</summary>
        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:10px">
          <div style="flex:1;min-width:320px">
            <div class="form-row"><label>授权页地址</label><input id="fsAuth" value="${esc(f.auth_url || "")}"></div>
            <div class="form-row"><label>Token 地址</label><input id="fsToken" value="${esc(f.token_url || "")}"></div>
            <div class="form-row"><label>用户信息地址</label><input id="fsUserinfo" value="${esc(f.userinfo_url || "")}"></div>
          </div>
          <div style="flex:1;min-width:320px">
            <div class="form-row"><label>应用凭证地址</label><input id="fsAppToken" value="${esc(f.app_token_url || "")}"></div>
            <div class="form-row"><label>Token 模式</label><select id="fsMode">
              ${opt("v3", "v3（推荐，Basic 认证）", f.token_mode || "v3")}${opt("legacy-v1", "legacy-v1（旧版）", f.token_mode || "v3")}</select></div>
            <div class="form-row"><label>Scope</label><input id="fsScope" value="${esc(f.scope || "")}" placeholder="contact:user.email:readonly"></div>
          </div>
        </div>
      </details>
    </div>

    <div data-ssopanel="dingtalk" style="display:none">
      <div class="tip-banner">在 <b>open-dev.dingtalk.com</b> 创建「企业内部应用」→ 凭证与基础信息取 AppKey / AppSecret（AppKey 即 Client ID）；<br>
        权限需开通「通讯录个人信息读权限」（返回 unionId、邮箱）；「登录与分享 → 回调域名」填 <code>${esc(base)}/callback</code>。</div>
      <div style="display:flex;gap:18px;flex-wrap:wrap">
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>启用</label>${onoff("dtOn", dt.enabled === 1)}</div>
          <div class="form-row"><label class="req">AppKey（Client ID）</label><input id="dtId" value="${esc(dt.app_id || "")}" placeholder="dingxxxxxxxxxxxxxxxx"></div>
          <div class="form-row"><label>AppSecret</label><input id="dtSec" type="password" placeholder="${dt.secret_set ? "已保存，留空不修改" : "凭证与基础信息 → AppSecret"}"></div>
        </div>
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>邮箱域名白名单</label><input id="dtDomain" value="${esc(dt.email_domain || "")}" placeholder="留空不限制"></div>
          <div class="form-row"><label>钉钉ID匹配属性</label><input id="dtAttr" value="${esc(dt.match_attr || "carLicense")}" placeholder="carLicense"></div>
          <div class="form-row"><label>联调模式</label>${mockSel("dtMock", dt.mock === 1)}</div>
        </div>
      </div>
      <details style="margin-top:4px"><summary style="cursor:pointer;color:var(--primary);font-size:13px">高级：接口地址 / Scope</summary>
        <div style="display:flex;gap:18px;flex-wrap:wrap;margin-top:10px">
          <div style="flex:1;min-width:320px">
            <div class="form-row"><label>授权页地址</label><input id="dtAuth" value="${esc(dt.auth_url || "")}"></div>
            <div class="form-row"><label>Token 地址</label><input id="dtToken" value="${esc(dt.token_url || "")}"></div>
          </div>
          <div style="flex:1;min-width:320px">
            <div class="form-row"><label>用户信息地址</label><input id="dtUserinfo" value="${esc(dt.userinfo_url || "")}"></div>
            <div class="form-row"><label>Scope</label><input id="dtScope" value="${esc(dt.scope || "openid")}" placeholder="openid"></div>
          </div>
        </div>
      </details>
    </div>

    <div data-ssopanel="wecom" style="display:none">
      <div class="tip-banner">在 <b>work.weixin.qq.com</b>「应用管理 → 自建应用」取 AgentId / Secret，「我的企业」取 CorpID；<br>
        在该应用的「企业微信授权登录 → Web 网页授权」中设置可信域名，回调填 <code>${esc(base)}/callback</code>。<br>
        <b>企业微信的 userid 会直接当作 VPN 账号名</b>（找不到同名账号时再按邮箱匹配），所以建议 LDAP 的 uid 与企微 userid 保持一致。</div>
      <div style="display:flex;gap:18px;flex-wrap:wrap">
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>启用</label>${onoff("wcOn", wc.enabled === 1)}</div>
          <div class="form-row"><label class="req">CorpID</label><input id="wcCorp" value="${esc(wc.app_id || "")}" placeholder="wwxxxxxxxxxxxxxxxx"></div>
          <div class="form-row"><label class="req">AgentId</label><input id="wcAgent" value="${esc(wc.agent_id || "")}" placeholder="1000002"></div>
          <div class="form-row"><label>应用 Secret</label><input id="wcSec" type="password" placeholder="${wc.secret_set ? "已保存，留空不修改" : "自建应用的 Secret"}"></div>
        </div>
        <div style="flex:1;min-width:320px">
          <div class="form-row"><label>邮箱域名白名单</label><input id="wcDomain" value="${esc(wc.email_domain || "")}" placeholder="留空不限制"></div>
          <div class="form-row"><label>企业微信ID匹配属性</label><input id="wcAttr" value="${esc(wc.match_attr || "carLicense")}" placeholder="carLicense"></div>
          <div class="form-row"><label>联调模式</label>${mockSel("wcMock", wc.mock === 1)}</div>
          <details style="margin-top:2px"><summary style="cursor:pointer;color:var(--primary);font-size:13px">高级：接口地址</summary>
            <div class="form-row" style="margin-top:8px"><label>授权页地址</label><input id="wcAuth" value="${esc(wc.auth_url || "")}"></div>
            <div class="form-row"><label>API 根地址</label><input id="wcApi" value="${esc(wc.api_base || "")}" placeholder="https://qyapi.weixin.qq.com"></div>
          </details>
        </div>
      </div>
    </div>

    <div style="margin-top:16px;border-top:1px solid var(--line);padding-top:14px">
      <h4 style="margin:0 0 8px">客户端对接参数（三渠道通用）</h4>
      <table style="font-size:13px">
        <tr><th style="width:210px">发起登录</th><td><code>POST /api/v1/device/start</code>，body 可带 <code>{"provider":"feishu|dingtalk|wecom"}</code></td></tr>
        <tr><th>轮询结果</th><td><code>POST /api/v1/device/poll</code> → <code>{status,username,vpn_token}</code></td></tr>
        <tr><th>下载个人配置</th><td><code>POST /api/v1/profile/feishu</code>（凭 device_verifier，免密）</td></tr>
        <tr><th>账号密码下载</th><td><code>POST /api/v1/profile/account</code></td></tr>
        <tr><th>服务间校验</th><td><code>POST /api/v1/token/verify</code>（Bearer 服务校验密钥）</td></tr>
        <tr><th>健康检查</th><td><code>GET /healthz</code></td></tr>
        <tr><th>回调地址（三个渠道都填这个）</th><td><code>${esc(base)}/callback</code></td></tr>
      </table>
      <p class="muted" style="font-size:12.5px;margin-top:10px">
        OpenVPN 侧无需外部网关脚本：<code>sslvpn auth-verify</code> 直接核销 <code>FS1.</code> 口令；
        口令与账号绑定，重放、过期、跨账号使用都会被拒绝并记入「认证日志」。
      </p>
    </div>
  </div>`;
  ssoSwitchTab(ssoTab);
}

function ssoSwitchTab(k) {
  ssoTab = k;
  document.querySelectorAll("[data-ssotab]").forEach(b => {
    const on = b.dataset.ssotab === k;
    b.style.fontWeight = on ? "600" : "400";
    b.style.color = on ? "var(--primary)" : "";
    b.style.borderBottom = on ? "2px solid var(--primary)" : "2px solid transparent";
    b.style.padding = "6px 12px";
  });
  document.querySelectorAll("[data-ssopanel]").forEach(p => {
    p.style.display = p.dataset.ssopanel === k ? "block" : "none";
  });
}

// 清空「回调基地址」：保存后恢复跟随全局公网地址（域名 + 端口），三个渠道一起生效
function ssoFollowGlobal() {
  const el = document.getElementById("ssoBase");
  if (!el) return;
  el.value = "";
  toast("已清空，点「保存全部」后三个渠道的回调地址将跟随全局公网地址（含端口）", true);
}

async function ssoSave() {
  const body = {
    base_url: normalizeHttps(fv("ssoBase")), default_provider: fv("ssoDefault"),
    device_ttl: +fv("ssoTtl") || 300, token_ttl: +fv("ssoTok") || 60,
    verify_secret: fv("ssoSecret"), mock_all: +fv("ssoMockAll"),
    providers: [
      { key: "feishu", enabled: +fv("fsOn"), mock: +fv("fsMock"), app_id: fv("fsId"), secret: fv("fsSec"),
        tenant_key: fv("fsTenant"), email_domain: fv("fsDomain"), match_attr: fv("fsAttr"),
        token_mode: fv("fsMode"), scope: fv("fsScope"),
        auth_url: fv("fsAuth"), token_url: fv("fsToken"), userinfo_url: fv("fsUserinfo"), app_token_url: fv("fsAppToken") },
      { key: "dingtalk", enabled: +fv("dtOn"), mock: +fv("dtMock"), app_id: fv("dtId"), secret: fv("dtSec"),
        email_domain: fv("dtDomain"), match_attr: fv("dtAttr"), scope: fv("dtScope"),
        auth_url: fv("dtAuth"), token_url: fv("dtToken"), userinfo_url: fv("dtUserinfo") },
      { key: "wecom", enabled: +fv("wcOn"), mock: +fv("wcMock"), app_id: fv("wcCorp"), agent_id: fv("wcAgent"),
        secret: fv("wcSec"), email_domain: fv("wcDomain"), match_attr: fv("wcAttr"),
        auth_url: fv("wcAuth"), api_base: fv("wcApi") },
    ],
  };
  const r = await api("/system/updateFeishu", { body });
  toast(r.msg, r.code === 1);
  if (r.code === 1) enter("sso");
}

async function ssoTestDoc() {
  const r = await api("/system/testFeishu", { body: { provider: ssoTab } });
  toast(r.msg, r.code === 1);
}

/* ================= 域名分流（按用户，写 CCD） ================= */
let _drCache = { list: [], services: [], pending_names: [] };
let _drSvcOpts = `<option value="0">全部实例</option>`;
let _drAllUsers = null;
const DR_USERBOX_STYLE = "flex:1;max-width:520px;max-height:170px;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:#fff";
const DR_UROW_STYLE = "display:flex;align-items:center;gap:8px;padding:4px 2px;font-size:13.5px;cursor:pointer";

async function pageDomain(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">🌐 域名分流</h3>
      <div class="inline">
        <button class="ghost" onclick="drResolveAll()">⟳ 重新解析</button>
        <button class="ghost" onclick="drApply()">⚡ 重启实例（仅实例级）</button>
        <button class="primary" onclick="drAddModal()">＋ 添加域名</button>
      </div></div>
    <div class="tip-banner" style="margin-bottom:12px">
      填域名 → 服务端按周期解析成 IPv4 → 以 <b>/32 主机路由</b> 写进<b>指定用户的 CCD 文件</b>。
      只有这些 IP 走 VPN，其余流量仍走本地网络。<b>改完不需要重启实例，用户重新连接 VPN 即生效</b>。
      CDN / 负载均衡类域名 IP 变动频繁，建议改用「推送路由」按网段配置。
    </div>
    <div id="drBox">${loading}</div></div>`;
  await drRender();
}

async function drRender() {
  const box = document.getElementById("drBox");
  if (!box) return;
  const d = await api("/domainRoute/list");
  _drCache = d.data || { list: [], services: [], pending_names: [] };
  const services = _drCache.services || [];
  _drSvcOpts = `<option value="0">全部实例</option>` +
    services.map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join("");
  const svcName = id => id ? ((services.find(s => s.id === id) || {}).name || `实例 #${id}`) : "全部实例";

  const rows = (_drCache.list || []).map(x => {
    const ips = (x.ips || []).map(ip => `<span class="badge gray" style="margin:1px 4px 1px 0">${esc(ip)}</span>`).join("")
      || `<span class="muted">未解析</span>`;
    const state = x.last_error ? badge(false, "解析失败", "解析失败")
      : ((x.ips || []).length ? badge(true, "已解析", "已解析") : badge(false, "待解析", "待解析"));
    const err = x.last_error ? `<div class="muted" style="font-size:12px;color:#f56c6c;margin-top:2px">${esc(x.last_error)}</div>` : "";
    const who = x.username
      ? `<span class="badge blue">👤 ${esc(x.username)}</span>`
      : `<span class="badge gray">🌐 全部用户</span>`;
    return `<tr>
      <td><b>${esc(x.domain)}</b>${x.note ? `<div class="muted" style="font-size:12px">${esc(x.note)}</div>` : ""}</td>
      <td>${who}</td>
      <td>${esc(svcName(x.service_id))}</td>
      <td>${ips}${err}</td>
      <td>${x.enabled ? state : badge(false, "已停用", "已停用")}</td>
      <td class="muted">${esc(x.resolved_text || "-")}<div style="font-size:12px">每 ${x.ttl || 300}s 刷新</div></td>
      <td class="nowrap">
        <button class="ghost" onclick="drResolve(${x.id})">解析</button>
        <button class="ghost" onclick="drToggle(${x.id},${x.enabled ? 0 : 1})">${x.enabled ? "停用" : "启用"}</button>
        <button class="ghost" onclick="drEditModal(${x.id})">编辑</button>
        <button class="ghost" onclick="drDel(${x.id})">删除</button>
      </td></tr>`;
  }).join("");

  const pending = _drCache.pending_names || [];
  box.innerHTML = `
    ${pending.length ? `<div class="tip-banner" style="margin-bottom:12px;border-color:#e6a23c">
      ⚠️ 实例级规则待生效：${pending.map(p => `<b>${esc(p)}</b>`).join("、")} —— 点「重启实例」后下发（按用户的规则不需要）。
    </div>` : ""}
    ${rows ? `<table><tr><th>域名</th><th>下发给</th><th>实例</th><th>解析到的 IP</th><th>状态</th><th>上次解析</th><th style="width:230px">操作</th></tr>${rows}</table>`
      : `<p class="muted" style="text-align:center;padding:30px 0">还没有域名分流规则</p>`}`;
}

// 用户名列表（缓存一次，供勾选）
async function drLoadUsers() {
  if (_drAllUsers) return _drAllUsers;
  try {
    const d = await api("/ccd/getAllUser");
    _drAllUsers = (d.data && d.data.users) || [];
  } catch (e) { _drAllUsers = []; }
  return _drAllUsers;
}

function drUserBoxHTML(selected) {
  const sel = new Set((selected || []).filter(Boolean));
  return `<div style="flex:1;max-width:520px;min-width:0">
    <input id="drUserSearch" placeholder="搜索用户名…" oninput="drFilterUsers()" style="max-width:100%;margin-bottom:6px">
    <div id="drUserList" style="${DR_USERBOX_STYLE}">
      ${(_drAllUsers || []).map(u => `<label style="${DR_UROW_STYLE}" data-name="${esc(u.toLowerCase())}">
        <input type="checkbox" value="${esc(u)}" ${sel.has(u) ? "checked" : ""}>
        <span>${esc(u)}</span></label>`).join("") || `<span class="muted">没有可选用户（可直接在下方手动填写）</span>`}
    </div>
  </div>`;
}

function drFilterUsers() {
  const kw = (document.getElementById("drUserSearch").value || "").trim().toLowerCase();
  document.querySelectorAll("#drUserList label").forEach(el => {
    const hit = !kw || el.dataset.name.includes(kw) || el.querySelector("input").checked;
    el.style.display = hit ? "flex" : "none";
  });
}

function drPickedUsers() {
  const picked = [...document.querySelectorAll("#drUserList input[type=checkbox]:checked")].map(x => x.value);
  const extra = (fv("drUsersExtra") || "").split(/[,，;；\s]+/).map(s => s.trim()).filter(Boolean);
  return [...new Set([...picked, ...extra])];
}

async function drAddModal() {
  await drLoadUsers();
  formModal("添加域名分流", `
    <div class="form-row" style="align-items:flex-start"><label class="req" style="padding-top:9px">域名</label><textarea id="drDomain" style="width:100%;max-width:100%;min-height:78px" placeholder="一行一个域名，也可用逗号/空格分隔，例如：&#10;oa.example.com&#10;erp.example.com&#10;crm.example.com（不支持通配符和 IP）"></textarea></div>
    <div class="form-row" style="align-items:flex-start"><label class="req" style="padding-top:9px">下发给用户</label>${drUserBoxHTML([])}</div>
    <div class="form-row"><label>手动补充</label><input id="drUsersExtra" placeholder="用户名，逗号分隔（可填未在列表中的账号）"></div>
    <div class="form-row"><label>生效实例</label><select id="drScope">${_drSvcOpts}</select></div>
    <div class="form-row"><label>刷新间隔</label><input id="drTtl" type="number" value="300" placeholder="秒">
      <span class="muted" style="margin-left:8px;font-size:12px">默认 300 秒重新解析一次</span></div>
    <div class="form-row"><label>备注</label><input id="drNote" placeholder="可选，如：办公 OA"></div>
    <div class="tip-banner" style="margin-top:10px">只对目标 <b>IP</b> 生效（OpenVPN 不支持按域名选路）；CDN 域名请改用「推送路由」。<b>同一用户可添加多个域名</b>，解析到的 IP 会合并去重写入该用户 CCD，保存后<b>用户重连即生效，不重启实例</b>。</div>`,
  async () => {
    const users = drPickedUsers();
    if (!users.length) throw new Error("请至少选择一个用户");
    const r = await api("/domainRoute/addMulti", {
      body: { domain: fv("drDomain"), service_id: +fv("drScope") || 0, usernames: users,
        ttl: +fv("drTtl") || 300, note: fv("drNote"), enabled: 1 }
    });
    if (r.code !== 1) throw new Error(r.msg);
    toast(r.msg || "已添加");
    await drRender();
  }, { width: 640 });
}

function drEditModal(id) {
  const x = (_drCache.list || []).find(v => v.id === id);
  if (!x) return;
  const userRow = x.username
    ? `<div class="form-row"><label>用户名</label><input id="drUser" value="${esc(x.username)}"></div>`
    : `<div class="form-row"><label>下发对象</label><span class="muted">全部用户（实例级，需重启实例生效）</span></div>`;
  formModal("编辑域名分流", `
    <div class="form-row"><label>域名</label><input value="${esc(x.domain)}" disabled></div>
    ${userRow}
    <div class="form-row"><label>生效实例</label><select id="drScope">${_drSvcOpts.replace(`value="${x.service_id}"`, `value="${x.service_id}" selected`)}</select></div>
    <div class="form-row"><label>刷新间隔</label><input id="drTtl" type="number" value="${x.ttl || 300}"></div>
    <div class="form-row"><label>备注</label><input id="drNote" value="${esc(x.note || "")}"></div>`, async () => {
    const body = { id, service_id: +fv("drScope") || 0, ttl: +fv("drTtl") || 300, note: fv("drNote"), enabled: x.enabled ? 1 : 0 };
    if (document.getElementById("drUser")) body.username = fv("drUser");
    const r = await api("/domainRoute/update", { body });
    if (r.code !== 1) throw new Error(r.msg);
    toast(r.msg || "已保存");
    await drRender();
  }, { width: 560 });
}

async function drToggle(id, enabled) {
  const r = await api("/domainRoute/update", { body: { id, enabled } });
  toast(r.code === 1 ? (r.msg || "已更新") : (r.msg || "操作失败"), r.code === 1);
  await drRender();
}

async function drDel(id) {
  if (!confirm("删除后该域名的路由会在用户下次重连时取消，确认删除？")) return;
  const r = await api("/domainRoute/delete", { body: { id } });
  toast(r.code === 1 ? (r.msg || "已删除") : (r.msg || "删除失败"), r.code === 1);
  await drRender();
}

async function drResolve(id) {
  const r = await api("/domainRoute/resolve", { body: { id } });
  toast(r.code === 1 ? (r.msg || "解析完成") : (r.msg || "解析失败"), r.code === 1);
  await drRender();
}

async function drResolveAll() {
  const r = await api("/domainRoute/resolve", { body: { id: 0 } });
  toast(r.code === 1 ? (r.msg || "已重新解析") : (r.msg || "解析失败"), r.code === 1);
  await drRender();
}

async function drApply() {
  if (!confirm("仅「实例级」规则需要重启实例；按用户的规则已即时写入 CCD，不需要此操作。继续重启待生效实例？")) return;
  const r = await api("/domainRoute/apply", { body: {} });
  toast(r.code === 1 ? (r.msg || "已应用") : (r.msg || "应用失败"), r.code === 1);
  await drRender();
}

/* ================= 系统管理员 ================= */
async function pageAdmins(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">🛡 管理员</h3>
      <div class="inline">
        <button class="primary" onclick="adminAddModal()">＋ 添加管理员</button>
        <button class="ghost" onclick="enter('admins')">⟳ 刷新</button>
      </div></div>
    <div id="admTable">${loading}</div>
    <p class="muted" style="margin-top:10px">ⓘ 管理员用于登录本管理后台；密码以 bcrypt 加密存储，编辑时留空密码表示不修改。至少需保留一个管理员。</p></div>`;
  renderAdminTable();
}
async function renderAdminTable() {
  const d = await api("/admin/list");
  const list = d.data.list || [];
  const rows = list.map(a => `<tr>
    <td>${a.id}</td>
    <td><b>${esc(a.username)}</b></td>
    <td>${esc(a.email || "-")}</td>
    <td>${a.status ? '<span class="badge ok">启用</span>' : '<span class="badge off">禁用</span>'}</td>
    <td>${a.super ? '<span class="badge blue">超级管理员</span>' : '<span class="badge gray">普通管理员</span>'}</td>
    <td class="muted">${esc(a.created_at || "-")}</td>
    <td class="inline" style="flex-wrap:nowrap">
      <a href="javascript:;" class="lk" onclick="adminEditModal(${a.id},'${esc(a.username)}','${esc(a.email || "")}',${a.status})">编辑</a>
      <a href="javascript:;" class="lk r" onclick="adminDel(${a.id},'${esc(a.username)}')">删除</a></td></tr>`).join("");
  document.getElementById("admTable").innerHTML = list.length ? `<table>
    <tr><th>ID</th><th>用户名</th><th>邮箱</th><th>状态</th><th>角色</th><th>创建时间</th><th>操作</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无管理员</p>`;
}
function adminAddModal() {
  formModal("添加管理员", `
    <div class="form-row"><label class="req">用户名</label><input id="adName" placeholder="字母数字组合"></div>
    <div class="form-row"><label class="req">密码</label><input id="adPass" type="password" placeholder="至少 8 位"></div>
    <div class="form-row"><label>邮箱</label><input id="adMail" placeholder="选填"></div>`,
    async () => {
      const r = await api("/admin/addAccount", { body: { username: fv("adName"), password: fv("adPass"), email: fv("adMail") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("管理员已创建"); enter("admins");
    });
}
function adminEditModal(id, name, email, status) {
  formModal("编辑管理员：" + esc(name), `
    <div class="form-row"><label>用户名</label><input id="aeName" value="${esc(name)}"></div>
    <div class="form-row"><label>新密码</label><input id="aePass" type="password" placeholder="留空则不修改密码"></div>
    <div class="form-row"><label>旧密码</label><input id="aeOldPass" type="password" placeholder="修改新密码时必填，用于验证身份"></div>
    <div class="form-row"><label>邮箱</label><input id="aeMail" value="${esc(email)}"></div>
    <div class="form-row"><label>状态</label><select id="aeSt"><option value="1">启用</option><option value="0">禁用</option></select></div>`,
    async () => {
      const np = fv("aePass"), op = fv("aeOldPass");
      if (np && !op) throw new Error("修改密码需要先填写旧密码验证身份");
      const r = await api("/admin/update", { body: { id, username: fv("aeName"), password: np,
        old_password: op, email: fv("aeMail"), status: +fv("aeSt") } });
      if (r.code !== 1) throw new Error(r.msg);
      toast("已更新"); enter("admins");
    });
  document.getElementById("aeSt").value = String(status);
}
function adminDel(id, name) {
  confirmModal("删除管理员", `将删除管理员 <b>${esc(name)}</b>，删除后无法用该账号登录。确定？`, async () => {
    const r = await api("/admin/delUser", { body: { id } });
    toast(r.msg, r.code === 1); enter("admins");
  });
}

/* ================= 授权管理 ================= */
async function pageLicense(main) {
  main.innerHTML = loading;
  let r;
  try { r = await api("/license/info"); } catch (e) { return; }
  const s = r.data || {};
  const map = { licensed: ["ok", "已授权"], trial: ["blue", "试用中"], expired: ["off", "未授权"] };
  const [cls, txt] = map[s.state] || ["gray", s.state || "未知"];
  const isLic = s.state === "licensed";
  const tip = s.state === "expired"
    ? `⚠ 试用已于 ${esc(s.trial_end)} 到期，除本页外的功能已锁定。请在下方粘贴许可串激活。`
    : (isLic ? `✓ 已授权给「${esc(s.company || s.customer || "-")}」，有效期至 ${esc(s.expire)}（剩 ${s.days_left} 天）。${s.unbound ? "该许可不绑定机器，同时仅授权 1 台在用。" : ""}`
             : `ⓘ 当前处于试用期，剩余 ${s.days_left} 天（截止 ${esc(s.trial_end)}）。试用到期后需激活许可才能继续使用。`);
  const licRows = isLic ? `
      <tr><td>授权客户（公司）</td><td>${esc(s.company || s.customer || "-")}</td></tr>
      <tr><td>授权邮箱</td><td>${esc(s.email || "-")}</td></tr>
      <tr><td>绑定方式</td><td>${s.unbound
        ? '<span class="badge blue" style="font-size:12px;padding:2px 8px">不绑定机器</span> &nbsp;同时仅 <b>' + esc(String(s.nodes || 1)) + '</b> 台在用'
        : '<span class="badge ok" style="font-size:12px;padding:2px 8px">绑定本机</span>'}</td></tr>
      <tr><td>许可编号</td><td style="font-family:monospace">${esc(s.lic_id || "-")}</td></tr>
      <tr><td>授权到期日</td><td>${esc(s.expire)}（剩 <b>${s.days_left}</b> 天）</td></tr>
      ${s.unbound && s.lock_machine ? `<tr><td>激活机器</td><td>${esc(s.lock_machine)}${s.lock_time ? "（" + esc(s.lock_time) + " 激活）" : ""}</td></tr>` : ""}` : "";
  main.innerHTML = `
  <div class="card" style="max-width:980px">
    <div class="topbar" style="align-items:center">
      <h3 style="margin:0">🔐 许可管理</h3>
      <span class="badge ${cls}" style="font-size:13px;padding:5px 12px">${txt}</span>
    </div>
    <div class="tip-banner" style="${s.state === "expired" ? "background:#fef0f0;border-color:#fde2e2;color:#f56c6c" : ""}">${tip}</div>
    <table>
      <tr><th style="width:180px">项目</th><th>值</th></tr>
      <tr><td>机器码</td><td><b id="licMachine" style="color:var(--primary);font-family:monospace;font-size:15px;letter-spacing:1px">${esc(s.machine)}</b>
        <a class="lk" style="margin-left:10px" onclick="licenseCopy()">复制</a>
        <span style="color:#909399;font-size:12px;margin-left:8px">（仅绑定机器的许可才需要提供）</span></td></tr>
      ${licRows || '<tr><td>授权到期日</td><td>-</td></tr>'}
      ${s.state === "licensed" ? "" : `<tr><td>试用期</td><td>${esc(String(s.trial_days || 15))} 天，截止 <b>${esc(s.trial_end || "-")}</b></td></tr>`}
      <tr><td>服务器时间</td><td>${esc(s.server_time || "-")}</td></tr>
      ${s.token_error ? `<tr><td>许可串异常</td><td style="color:#f56c6c">${esc(s.token_error)}</td></tr>` : ""}
    </table>
    <h3 style="margin:18px 0 10px">激活许可</h3>
    <textarea id="licToken" rows="4" placeholder="粘贴许可串（一长串字母数字，形如 eyJpZCI6...  .签名）"
      style="width:100%;box-sizing:border-box;font-family:monospace;font-size:12px;padding:9px;border:1px solid #dcdfe6;border-radius:4px;resize:vertical"></textarea>
    <div class="inline" style="margin-top:12px">
      <button class="primary" onclick="licenseActivate()">✓ 激活许可</button>
      <button class="orange" onclick="licenseCopy()">⧉ 复制机器码</button>
      ${isLic ? '<button class="danger" onclick="licenseClear()">✕ 解除激活</button>' : ""}
    </div>
    <details style="margin-top:16px">
      <summary style="cursor:pointer;color:#909399;font-size:12.5px">签发方式（内部参考，默认收起）</summary>
      <div class="tip-banner" style="display:block;margin-top:8px;background:#f4f4f5;border-color:#e9e9eb;color:#606266">
        <b>签发方式</b>（在授权端执行，私钥 <code>deploy/keys/license-private.pem</code> 不出签发机）：<br>
        <div style="margin:10px 0 4px"><b>① 不绑机器</b>（推荐，客户只需给邮箱 + 公司名）：</div>
        <code style="display:inline-block">./sslvpn license-gen -bind none -email 客户邮箱@xx.com -company "某某公司" -days 365</code>
        <div style="margin:10px 0 4px"><b>② 绑定机器</b>（客户先发来机器码）：</div>
        <code style="display:inline-block">./sslvpn license-gen -machine ${esc(s.machine)} -company "某某公司" -days 365</code>
        <div style="margin-top:10px;line-height:1.9">
          浮动许可同时仅限 <b>1 台</b>在用：换机时先在原机点「解除激活」，再到新机激活；<br>
          需要强约束（同一许可只能一台机器激活）时启用在线登记：<code>sslvpn license-registry</code> + 环境变量
          <code>SSLVPN_LICENSE_REGISTER</code> / <code>SSLVPN_LICENSE_SECRET</code>；<br>
          签发后可自检：<code>./sslvpn license-inspect -token '…'</code>
        </div>
      </div>
    </details>
  </div>`;
}
async function licenseActivate() {
  const t = (fv("licToken") || "").trim();
  if (!t) return toast("请先粘贴许可串", false);
  const r = await api("/license/activate", { body: { token: t } });
  if (r.code !== 1) return toast(r.msg, false);
  toast("✓ 授权已激活");
  enter("license");
}
function licenseCopy() {
  const el = document.getElementById("licMachine");
  const m = (el && el.textContent || "").trim();
  if (!m) return;
  if (navigator.clipboard) navigator.clipboard.writeText(m).then(() => toast("机器码已复制：" + m), () => prompt("复制机器码：", m));
  else prompt("复制机器码：", m);
}
function licenseClear() {
  confirmModal("解除激活", "解除后本机释放该许可占用（可换到另一台机器重新激活）；若仍在试用期则回到试用状态，否则系统会被锁定。确定解除？", async () => {
    const r = await api("/license/clear", { body: {} });
    if (r.code !== 1) return toast(r.msg, false);
    toast("已解除激活");
    enter("license");
  });
}

/* ================= 其它配置 ================= */
async function pageSys(main) {
  const cfg = await api("/linuxcc/get");
  const c = cfg.data;
  main.innerHTML = `<div class="card" style="max-width:900px">
    <h3>🎨 品牌设置（登录页与系统界面）</h3>
    <div class="form-row"><label>系统名称</label><input id="brName" value="${esc(BRAND.name)}" placeholder="如：KSVPN" maxlength="40"></div>
    <div class="form-row"><label>Logo 图片</label>
      <div class="inline" style="flex:1;gap:12px;align-items:center">
        <img id="brPrev" src="${esc(BRAND.logo_url)}" alt="logo"
          style="height:44px;max-width:220px;object-fit:contain;border:1px solid #ebeef5;border-radius:6px;padding:4px;background:#fff">
        <input type="file" id="brFile" accept="image/png,image/jpeg,image/webp,image/gif" style="display:none" onchange="brandUpload()">
        <button class="primary" onclick="document.getElementById('brFile').click()">⬆ 选择图片</button>
        <button class="orange" onclick="brandReset()">↺ 恢复默认</button>
      </div></div>
    <div class="form-row"><label></label><div class="muted" style="font-size:12px">支持 PNG / JPG / WEBP / GIF，小于 512KB，建议使用透明底方形图片</div></div>
    <div class="form-row"><label></label><button class="primary" onclick="brandSave()">✓ 保存名称</button></div>
  </div>
  <div class="card" style="max-width:900px">
    <h3>☑ 全局设置</h3>
    <div class="form-row"><label>服务器公网地址</label><input id="syHost" value="${esc(normalizeHttps(c.public_host))}" placeholder="vpn.example.com 或 1.2.3.4:58443（域名/IP 自动补 https://）" onblur="autoHttps(this)"></div>
    <div class="form-row"><label>客户端下载地址</label><input id="syDL" value="${esc(c.download_url || "")}" placeholder="域名或 IP，自动补 https://" onblur="autoHttps(this)"></div>
    <div class="form-row"><label>版权信息</label><input id="syCP" value="${esc(c.copyright || "")}" placeholder="留空显示默认：© 2026-至今 Power by KingStronger"></div>
    <div class="form-row"><label>版权链接</label><input id="syCPURL" value="${esc(c.copyright_url || "")}" placeholder="域名或 IP，自动补 https://" onblur="autoHttps(this)"></div>
    <div class="form-row"><label>用户自助注册</label><select id="syRegU" style="max-width:180px">
      <option value="1" ${c.register_user === "1" ? "selected" : ""}>开放</option>
      <option value="0" ${c.register_user !== "1" ? "selected" : ""}>关闭</option></select></div>
    <div class="form-row"><label></label><button class="primary" onclick="sysSave()">✓ 更新</button></div>
  </div>`;
}
async function brandSave() {
  const name = (fv("brName") || "").trim();
  if (!name) return toast("系统名称不能为空", false);
  const r = await api("/system/updateBrand", { body: { name } });
  if (r.code !== 1) return toast(r.msg, false);
  BRAND.name = name;
  document.title = name + " 管理系统";
  toast("系统名称已更新");
  enter("sys"); // 重新渲染顶栏品牌
}
async function brandUpload() {
  const inp = document.getElementById("brFile");
  const f = inp.files && inp.files[0];
  if (!f) return;
  if (f.size > 512 * 1024) { inp.value = ""; return toast("图片请小于 512KB", false); }
  toast("正在上传…");
  const fd = new FormData();
  fd.append("file", f);
  let r;
  try { r = await apiUpload("/system/uploadLogo", fd); }
  catch (e) { return toast("上传失败: " + e.message, false); }
  if (r.code !== 1) { inp.value = ""; return toast(r.msg, false); }
  BRAND.logo_url = r.data.logo_url;
  BRAND.custom_logo = true;
  toast("Logo 已更新");
  enter("sys");
}
function brandReset() {
  confirmModal("恢复默认 Logo", "将移除自定义 Logo，恢复为内置 Logo。系统名称不受影响。确定？", async () => {
    const r = await api("/system/resetLogo", { body: {} });
    if (r.code !== 1) return toast(r.msg, false);
    BRAND.logo_url = "/logo.png";
    BRAND.custom_logo = false;
    toast("已恢复默认 Logo");
    enter("sys");
  });
}
async function sysSave() {
  const r = await api("/linuxcc/update", { body: {
    sys_name: BRAND.name, public_host: normalizeHttps(fv("syHost")),
    download_url: normalizeHttps(fv("syDL")), copyright: fv("syCP"), copyright_url: normalizeHttps(fv("syCPURL")), register_user: fv("syRegU") } });
  if (r.code !== 1) return toast(r.msg, false);
  BRAND.copyright = fv("syCP");
  BRAND.copyright_url = fv("syCPURL");
  toast("全局设置已保存");
  enter("sys"); // 刷新页脚
}

/* ================= 防火墙 ================= */
async function pageFW(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">🧱 访问控制规则</h3>
      <button class="primary" onclick="fwAddModal()">＋ 添加规则</button></div>
    <div id="fwTable">${loading}</div></div>`;
  const d = await api("/fw/getPortRuleList");
  const rows = (d.data.list || []).map(x => `<tr><td>${x.id}</td><td><b>${x.port}</b></td><td>${esc(x.proto)}</td>
    <td>${badge(x.action === "ACCEPT", x.action, x.action)}</td><td>${esc(x.source)}</td><td>${esc(x.note || "-")}</td></tr>`).join("");
  document.getElementById("fwTable").innerHTML = `
    <p class="muted" style="margin-bottom:10px">出站网卡：<b>${esc(d.data.out_iface)}</b>，出口 IP：<b>${esc(d.data.out_ip)}</b>（VPN 流量 SNAT 伪装随实例自动配置）</p>
    <table><tr><th>ID</th><th>端口</th><th>协议</th><th>动作</th><th>来源</th><th>备注</th></tr>${rows}</table>`;
}
function fwAddModal() {
  formModal("添加防火墙规则", `
    <div class="form-row"><label class="req">端口</label><input id="fwPort" type="number"></div>
    <div class="form-row"><label>协议</label><select id="fwProto"><option>tcp</option><option>udp</option></select></div>
    <div class="form-row"><label>动作</label><select id="fwAct"><option>ACCEPT</option><option>DROP</option></select></div>
    <div class="form-row"><label>来源网段</label><input id="fwSrc" value="0.0.0.0/0"></div>
    <div class="form-row"><label>备注</label><input id="fwNote"></div>`, async () => {
    const r = await api("/fw/addPortRule", { body: { port: +fv("fwPort"), proto: fv("fwProto"),
      action: fv("fwAct"), source: fv("fwSrc"), note: fv("fwNote") } });
    if (r.code !== 1) throw new Error(r.msg); toast("规则已生效"); enter("fw");
  });
}

/* ================= 日志中心：用户认证 ================= */
async function pageAuthLog(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">🛡 认证日志</h3>
      <div class="inline">
        <input id="alKw" placeholder="过滤关键字" style="width:180px" oninput="renderAuthLog()">
        <button class="primary" onclick="renderAuthLog()">🔍 搜索</button>
      </div></div>
    <div id="authLogBox">${loading}</div></div>`;
  await renderAuthLog();
}
let _accessEntries = [];
async function renderAuthLog() {
  const box = document.getElementById("authLogBox");
  if (!_accessEntries.length) {
    const d = await api("/log/access");
    _accessEntries = d.data.list || [];
  }
  const kw = (fv("alKw") || "").toLowerCase();
  let list = _accessEntries;
  if (kw) list = list.filter(e => (e.msg + e.type + e.ip).toLowerCase().includes(kw));
  const rows = list.slice(-200).reverse().map(e => `<tr>
    <td class="muted">${esc(e.date)}</td>
    <td>${badge(e.type !== "ERROR", e.type, "失败")}</td>
    <td>${esc(e.msg)}</td>
    <td>${esc(e.ip || "-")}</td></tr>`).join("");
  box.innerHTML = rows ? `<table><tr><th>时间</th><th>状态</th><th>信息</th><th>来源IP地址</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无认证记录</p>`;
}

/* ================= 日志中心：系统日志 ================= */
async function pageSysLog(main) {
  main.innerHTML = `<div class="card">
    <div class="topbar"><h3 style="margin:0">📄 系统操作日志</h3>
      <button class="ghost" onclick="enter('syslog')">⟳ 刷新</button></div>
    <div id="sysLogBox">${loading}</div></div>`;
  const d = await api("/syslog/list");
  const rows = (d.data.list || []).map(e => `<tr>
    <td>${esc(e.admin)}</td><td><span class="badge blue">${esc(e.action)}</span></td>
    <td>${esc(e.detail)}</td><td>${esc(e.ip)}</td>
    <td class="muted">${esc(e.created_at)}</td></tr>`).join("");
  document.getElementById("sysLogBox").innerHTML = rows ? `<table>
    <tr><th>账户/邮箱</th><th>类型</th><th>详情</th><th>IP</th><th>操作记录日期时间</th></tr>${rows}</table>`
    : `<p class="muted" style="text-align:center;padding:30px 0">暂无日志</p>`;
}

/* ================= 启动 ================= */
(async function boot() {
  applyTheme(currentTheme());   // 先套皮肤，登录页也生效
  await loadBrand();
  if (!token) return renderLogin();
  try {
    const d = await api("/account/systeminfo");
    sysInfo = d.data;
    enter("dash");
  } catch (e) { renderLogin(); }
})();
