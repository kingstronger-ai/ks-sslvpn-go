/* KSVPN 授权档位守卫：按许可档位隐藏未授权的功能菜单与页面内区块。
   仅做界面隐藏；后端 API 对各功能均有档位硬拦截（403 + 升级提示）兜底。 */
(function () {
  var PAGE_FEATURE = {
    ccd: "ccd",
    ldap: "ldap",
    domain: "domain_route",
    clientdl: "client_download",
    sso: "sso"
  };
  // 页面内区块/按钮的功能键 -> {label, tier}，用于生成锁定提示
  var FEATURE_META = {
    domain_route:     { label: "域名分流",             tier: "专业版" },
    sso:              { label: "扫码登录",             tier: "专业版" },
    ccd:              { label: "CCD 高级配置",         tier: "专业版" },
    ldap:             { label: "LDAP 目录集成",        tier: "专业版" },
    client_download:  { label: "客户端分发与下载管控", tier: "专业版" },
    multi_instance:   { label: "新增实例 / 集群部署",  tier: "企业版" },
    private_issuance: { label: "私有化签发与在线登记", tier: "企业版" },
    acme_auto_renew:  { label: "证书自动续签",         tier: "企业版" }
  };
  var allowed = null; // null=未知（不隐藏）；否则为 {featureKey:true} 映射

  function token() {
    try { return localStorage.getItem("sslvpn_token") || ""; } catch (e) { return ""; }
  }

  // 供 app.js 调用：档位未知时返回 true（后端仍会硬拦截），避免网络抖动误隐藏
  window.tierAllow = function (key) {
    return allowed === null ? true : !!allowed[key];
  };

  // 供 app.js 调用：把某个面板替换成统一的「未授权」提示
  window.tierLockBox = function (key, title) {
    var m = FEATURE_META[key] || { label: "该功能", tier: "更高档位" };
    return '<div class="tier-lock-box"><div class="topbar">' +
      '<h3 style="margin:0">🔒 ' + (title || m.label) + '</h3>' +
      '<span class="badge off">' + m.tier + '功能</span></div>' +
      '<div class="tip-banner" style="margin-top:10px">' +
      'ⓘ <b>' + m.label + '</b>属于' + m.tier + '功能，当前授权档位未开启。' +
      '可在「许可管理」查看当前档位；如需启用，请联系作者获取授权（详见文档站「捐赠与支持」）。' +
      '服务端已对该功能做硬拦截，未授权调用会返回 403。</div></div>';
  };

  function refresh() {
    var t = token();
    if (!t) { allowed = null; apply(); return; }
    fetch("/api/v1/license/info", {
      headers: { "Authorization": "Bearer " + t },
      credentials: "include"
    }).then(function (r) { return r.json(); }).then(function (d) {
      var map = {};
      var feats = (d && d.data && d.data.features) || [];
      for (var i = 0; i < feats.length; i++) map[feats[i]] = true;
      allowed = map;
      apply();
    }).catch(function () { /* 查询失败不改动菜单（后端仍会拦截） */ });
  }

  function apply() {
    if (!allowed) return;
    // ① 侧栏整页菜单
    var items = document.querySelectorAll("a[data-nav]");
    for (var i = 0; i < items.length; i++) {
      var k = items[i].getAttribute("data-nav");
      var f = PAGE_FEATURE[k];
      if (!f) continue;
      items[i].style.display = allowed[f] ? "" : "none";
    }
    // ② 页面内按钮 / 区块（data-feature）
    var blocks = document.querySelectorAll("[data-feature]");
    for (var j = 0; j < blocks.length; j++) {
      var el = blocks[j];
      var key = el.getAttribute("data-feature");
      var ok = !!allowed[key];
      if (el.getAttribute("data-feature-mode") === "replace") {
        // 面板内容可能被异步渲染覆盖，以是否含锁定提示为准，保证幂等
        if (!ok && !el.querySelector(".tier-lock-box")) {
          el.innerHTML = window.tierLockBox(key, el.getAttribute("data-feature-title"));
        }
      } else {
        el.style.display = ok ? "" : "none";
      }
    }
  }

  // SPA 重新渲染侧栏/页面后自动再次应用
  if (typeof MutationObserver === "function") {
    new MutationObserver(function () { apply(); })
      .observe(document.documentElement, { childList: true, subtree: true });
  }

  // 登录 / 注销（token 变化）时重新拉取许可信息
  var last = null;
  setInterval(function () {
    var t = token();
    if (t !== last) { last = t; refresh(); }
  }, 1200);

  refresh();
})();
