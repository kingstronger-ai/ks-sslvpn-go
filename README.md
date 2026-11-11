# SSLVPN-Go

**OpenVPN 企业远程接入 Web 管理系统**。后端使用 Go 单二进制实现，内置中文管理前端，
Docker Compose 一键部署。

> 用途：企业员工远程接入内网（OpenVPN Server 管理）。仅面向企业内网远程办公场景，
> 请遵守《中国网络安全法》等法律法规。

## 快速开始

```bash
docker compose up -d --build
# 浏览器访问（自签证书，接受风险继续）
# https://服务器IP:58443   默认账号 admin / ChangeMe（容器内仍为 8443）
```

首个 VPN 实例监听 `51194/udp`（容器内外同号，宿主侧映射 `51194:51194/udp`），管理页在 `58443/tcp`；多实例请在 `docker-compose.yml` 追加端口映射。

### NAS / 群晖 / Unraid（绑定目录）

交付包**只带标准 `docker-compose.yml`**，不含 `docker-compose.nas.yml`。NAS 设备建议把命名卷换成
宿主机绑定目录以便快照与备份，**完整可复制模板见部署文档站「开始部署 → NAS 与离线镜像」**
（本站是唯一维护点，交付包不再分发该文件）。

离线时可从标准文件派生：复制 `docker-compose.yml` 为 `docker-compose.nas.yml`，把 `volumes:` 两行改成
`- /你的/数据目录/sslvpn/data:/var/lib/sslvpn` 与 `- /你的/数据目录/sslvpn/openvpn:/etc/openvpn`，
删掉文件末尾的命名卷声明；`cap_add` / `devices` / `sysctls` 三项不能删。启动用
`docker compose -f docker-compose.nas.yml up -d --build`，访问 `https://<NAS地址>:58443`。

> **不要改名覆盖 `docker-compose.yml`**：命名卷与绑定目录指向不同位置，直接覆盖会让容器挂到空数据卷上，
> 看起来像数据全部丢失。请始终用 `-f` 指定文件启动；之后升级解压交付包也不会覆盖这份模板。

## 授权与试用

> **版本分档**：许可分为社区版 / 专业版 / 企业版，高级功能按档位拦截。试用期为社区版档位，
> 签发方式与档位说明见本章末尾「版本档位」；各档价格与购买方式见文末「捐赠与支持」。

- **默认试用 15 天**：首次启动写入试用起点（可用环境变量 `SSLVPN_TRIAL_DAYS` 调整）。
- 试用到期且未激活许可时，除「授权管理」外的所有功能接口返回 `402`，登录仍可用，前端会自动
  跳到授权页。
- 许可为 **Ed25519 签名串**，两种模式：**绑定机器码** 或 **不绑机器（浮动许可，仅限 1 台在用）**。
- 界面：系统管理 → **授权管理**（机器码、状态、剩余天数、档位、用户数上限与实时用量、粘贴激活、解除激活）。
- **可选用户数上限**：签发时加 `-max-users N` 限制 VPN 账号总数；不传或为 0 表示不限制（详见本章「用户数上限」）。
- 签发（授权端，私钥 `deploy/keys/license-private.pem` 不要放进镜像）：

```bash
# ① 不绑机器（常用）：只需客户邮箱 + 公司名称，客户拿到就能激活
./sslvpn license-gen -bind none -email 421381118@qq.com -company "某某科技有限公司" -days 365

# ② 绑定机器：目标服务器先执行 docker exec sslvpn-go sslvpn license-info 取机器码
./sslvpn license-gen -machine 908B-ADFD-D055-BFC0 -company "某某科技有限公司" -days 365

# 自检 / 固定到期日 / 指定台数 / 限制用户数
./sslvpn license-inspect -token '<许可串>'
./sslvpn license-gen -bind none -email 421381118@qq.com -company "X公司" -expire 2027-12-31 -nodes 1
./sslvpn license-gen -bind none -email 421381118@qq.com -company "X公司" -edition pro -max-users 50
```

> **许可编号**：不传 `-id` 时 `license-gen` 从 **1** 开始按序号自增，序号持久化在与私钥同目录的
> `license.seq`（可用 `-seq-file` 指定其它位置）。显式指定 `-id 100` 会把序号推进到 100，下次自动生成 101；绑定机器码的许可同样带编号，前端「许可编号」不再显示 `-`。
> 更换签发机时请把 `license.seq` 一起迁移，避免编号重复。

浮动许可（`-bind none`）默认 `-nodes 1`，即**同时只允许 1 台机器激活**：

- **纯离线**（默认）：首次激活在本地记录机器，换机需回原机点「解除激活」；无法阻止许可串被复制到第二台机器。
- **在线登记**（硬约束，可选）：授权方跑一个登记服务，客户的机器激活时占用席位，第二台机器会被拒绝。

```bash
# 授权方：启动登记服务（一个进程即可，记录写入 JSON）
sslvpn license-registry -addr :8790 -secret 'your-secret' -file /var/lib/license-registry.json

# 客户机（docker-compose.yml 的 environment 里加）
#   SSLVPN_LICENSE_REGISTER=http://授权方IP:8790   # 登记服务是明文 HTTP，跨公网请套 HTTPS 反代
#   SSLVPN_LICENSE_SECRET=your-secret
```

> **「同时仅限 1 台在用」的准确含义**：签发时 `-bind none` 默认 `-nodes 1`，但纯离线模式（不配
> `SSLVPN_LICENSE_REGISTER`）只是**软约束**——客户端只在自己库里记首次激活的机器码，
> 无法阻止把同一个许可串复制到另一台干净的机器上激活。要做**硬约束**，必须启用上面的在线登记服务：
> 它按许可编号 `id` 占座，同一 `id` 被第二台机器激活时直接拒绝（`-nodes` 目前仅作展示/记录）。
> 签发时不要漏掉自动生成的 `id`，否则登记服务会提示「浮动许可缺少许可编号」。
>
> 常用运维命令（授权方机器上执行）：
> ```bash
> # 查看当前占用
> curl -H 'X-License-Secret: your-secret' http://127.0.0.1:8790/list
> # 原机器已不在时强制回收席位（不要带 machine 字段，否则会被「只能由已激活机器解除」拒绝）
> curl -X POST -H 'X-License-Secret: your-secret' -H 'Content-Type: application/json' \
>      -d '{"id":"1"}' http://127.0.0.1:8790/release
> ```
> 换机时先在原机「解除激活」会自动释放席位；换许可（例如社区版换专业版）也建议先解除激活再粘贴新串。

签发端构建（在开发机）：

```bash
cd backend && go build -o sslvpn ./cmd/sslvpn
```

> 说明：授权拦截只作用于 Web/API 层，已建立的 OpenVPN 隧道与 `auth-verify` 认证不受影响。

### 用户数上限（可选，默认不限制）

签发时加 `-max-users N` 会把许可绑定到最多 `N` 个 VPN 账号（许可负载字段 `mu`）。**不传、填 0 或旧许可串（无 `mu`）都表示不限制用户数**；用户数与 `-edition` 档位彼此独立，可任意组合。

```bash
# 最多 50 个 VPN 用户 + 专业版功能
./sslvpn license-gen -bind none -email 421381118@qq.com -company "某某科技有限公司" \
    -edition pro -max-users 50

# 签发输出与自检都会显示「用户上限: 50 人」
./sslvpn license-inspect -token '<许可串>'
```

- **统计口径**：`account` 表全部账号（含禁用账号），避免禁用/启用绕过；后台管理员账号不计入。
- **拦截范围**：新增用户、批量导入、自助注册、LDAP 同步与导入全部走同一校验，达到上限返回应用层 `403`「当前许可最多允许 N 个 VPN 用户，已有 M 个…」。删除闲置账号立即释放额度。
- **页面显示**：「授权管理」显示上限 / 已用 / 剩余；「VPN 用户列表」顶部显示用量条，额度用尽时「添加用户」按钮置灰。
- **三个维度别混淆**：`-nodes` 管服务器台数、`-max-users` 管账号总数、实例配置的 `max_clients` 管同时在线连接数。
- 更换为更大用户数的许可后，需在「授权管理」先解除激活再粘贴新许可串（或换新机后重新激活）。

### 版本档位（社区版 / 专业版 / 企业版）

许可负载中的 `ed`（Edition）决定档位；也可用 `ft`（Features）给出显式功能清单（优先级更高）。
服务端按档位**硬拦截**高级功能接口，前端按 `/api/v1/license/info` 返回的 `tier` / `features` 同步隐藏无权菜单。

| 档位 | `-edition` 值 | 可用高级功能 |
| --- | --- | --- |
| 社区版 | `community`（默认，不传即为该档） | 核心 VPN：用户管理、本地密码 + TOTP、基础路由 / iroute、防火墙、日志审计、备份恢复、SMTP、品牌自定义 |
| 专业版 | `pro` | ＋域名分流、三渠道扫码登录（SSO）、CCD 高级配置、LDAP / AD 目录集成、桌面客户端分发与下载管控 |
| 企业版 | `enterprise` | ＋多实例 / 集群部署、私有化许可签发与在线登记、证书自动续签（ACME） |

功能键（`ft` 或 `-features`）：`domain_route` `sso` `ccd` `ldap` `client_download`（专业版），
`multi_instance` `private_issuance` `acme_auto_renew`（企业版）。

```bash
# 专业版 / 企业版许可（不传 -edition 即社区版）
./sslvpn license-gen -bind none -email 421381118@qq.com -company "某某科技有限公司" -expire 2030-12-31 -edition pro
./sslvpn license-gen -bind none -email 421381118@qq.com -company "某某科技有限公司" -edition enterprise

# 精确指定功能清单（逗号分隔，优先于档位推导）
./sslvpn license-gen -bind none -email 421381118@qq.com -company "某某科技有限公司" -edition pro -features domain_route,sso

# 自检：输出会显示档位与开启功能
./sslvpn license-inspect -token '<许可串>'
```

> 未授权时高级接口返回应用层 `403`「XX 为专业版/企业版功能，当前授权档位未开启」。
> 两个保护项：`/profile/account` 同时承载本地账号 / TOTP 客户端登录，**不按 LDAP 拦截**；
> 既有实例的管理不受限，仅**新增实例**需要企业版档位。试用期为社区版，可完整体验核心 VPN。

## 在线升级（检测 → 确认 → 自动备份 → 回滚）

后台「系统设置 → 版本升级」提供版本检测与一键升级。设计上**容器内不持有宿主机 Docker 权限**：
Web 端只负责检测版本、展示更新说明、记录用户确认与展示进度；真正的备份、替换、重建、回滚由宿主机上的
`deploy/upgrade-agent.sh` 执行。两者通过数据卷内的 `request.json` / `status.ini` / `backups.txt` / `log.txt`
通信，**不需要挂载 docker.sock，也不需要改动 docker-compose.yml 的卷配置**。

### 一次性部署（每个服务器一次）

```bash
# ① 部署含本功能的版本包（顶层目录 sslvpn-go/，原地覆盖解压，目录名不能变）
cd /opt && tar -xzf /opt/sslvpn-go/sslvpn-go-v1.2.2.tar.gz -C /opt
cd /opt/sslvpn-go && docker compose up -d --build

# ② 安装宿主机升级代理（systemd 常驻，自动拉起）
bash deploy/install-upgrade-agent.sh

# ③ 配置更新源：在 docker-compose.yml 的 environment 增加一行，然后重建容器
#      - SSLVPN_UPDATE_URL=file:///var/lib/sslvpn/upgrade/version.json
#    cd /opt/sslvpn-go && docker compose up -d
#    （国内可把 version.json 放到 Gitee 仓库或自建站点，填 https:// 地址；
#     例如 - SSLVPN_UPDATE_URL=https://gitee.com/KingStrongerGee/ssvpn/raw/main/version.json）

# ④ 放置更新源与升级包
cp deploy/version.json.example /opt/sslvpn-upgrade/version.json
#    编辑 version.json：把 sha256 换成实际包的 sha256，package 指向包路径
mkdir -p /opt/sslvpn-upgrade/packages
cp sslvpn-go-v1.2.2.tar.gz /opt/sslvpn-upgrade/packages/
```

代理会每 5 秒把宿主机 `/opt/sslvpn-upgrade/version.json` 同步进容器，供 `file://` 更新源读取；
升级包请放在 `/opt/sslvpn-upgrade/packages/`（不要放在 `/opt/sslvpn-go/` 内，回滚时该目录会被整体改名保留）。

`version.json` 字段：

| 字段 | 说明 |
| --- | --- |
| `version` | 目标版本号（语义版本，需大于当前版本） |
| `released_at` / `notes` | 发布日期与更新说明，展示在检测卡片里 |
| `package` | `http(s)://` 下载地址，或**宿主机上的包绝对路径**（推荐放 `packages/` 下） |
| `sha256` | 包的 sha256（64 位小写十六进制），**必填**；校验不通过绝不解压 |
| `min_version` | 本次升级要求的最低当前版本，低于它会被拒绝 |

### 使用流程

1. 「检查更新」→ 只读拉取 `version.json`，显示新版本、更新说明、包与 sha256。
2. 点击「确认升级」→ 二次确认弹窗说明会中断服务、会自动备份、可回滚。
3. 代理按阶段执行并回报进度：**备份 → 取包 → 校验 → 覆盖 → 重建 → 健康检查**。
4. 构建或健康检查失败时**自动回滚**；成功后也可在备份列表点「回滚」手动回退。

### 备份与回滚

每次升级前代理会在 `/opt/sslvpn-upgrade/backups/<备份ID>/` 生成完整快照：源码 tar、`docker-compose.yml`
（含端口/环境变量等自定义）、两个命名卷 `sslvpn-data` / `sslvpn-openvpn` 的 tar、当前镜像 tag。
升级解压后**保留现网 compose**，避免覆盖自定义配置；新包模板另存为 `compose.new.yml` 供对比。

回滚会恢复源码、配置与两个卷，并用备份时的镜像直接启动（无需联网重新构建）；升级失败的现场目录
保留为 `/opt/sslvpn-go.failed-<备份ID>` 便于排查。**回滚会把数据卷恢复到升级前，升级后新增的数据会丢失**。

代理任何情况下都不会执行 `docker compose down -v` 或删除数据卷；升级/回滚都必须保持目录名
`/opt/sslvpn-go` 不变，否则 compose 项目名变化会挂到空卷上（看起来像数据全部丢失）。

### 安全与手工兜底

- `POST /upgrade/apply` 只接受 `confirm` 字段，**下载地址与 sha256 一律由服务端从更新源重新读取**，
  管理端请求里夹带的 `package` 不会被采信，避免注入任意 URL 让宿主机代理下载执行。
- 所有升级接口需要管理员登录；代理与容器之间只传纯文本状态与 JSON 请求，不开放任何容器外执行接口。
- 未部署代理时页面会提示「代理未在线」，此时仍可按传统方式手工升级：备份两个卷 → 在 `/opt` 下
  `tar -xzf 新包 -C /opt` → `docker compose up -d --build` → `curl -k https://127.0.0.1:58443/healthz`。
- 升级会重建容器，VPN 与管理页面中断约 1–2 分钟，建议在维护窗口操作。

## 架构

```
浏览器 ──HTTPS:8443──► Go 进程（内嵌前端 SPA + API + 自签 TLS）
                        │
                        ├─ SQLite (/var/lib/sslvpn/data/sslvpn.db)
                        ├─ OpenVPN 多实例进程管理 (/etc/openvpn/instance/<名>/server.conf)
                        ├─ easy-rsa PKI (/var/lib/sslvpn/pki)
                        ├─ auth-verify 子命令（OpenVPN 认证回调，读库校验）
                        └─ iptables（端口放行 + SNAT 伪装自动配置）
```

- **单二进制**：Web 前端、API、OpenVPN 认证回调（`sslvpn auth-verify`）都在一个程序里
- **无 PHP / 无外部数据库依赖**：内嵌 SQLite（WAL 模式）
- **配置模板渲染**：`server.conf` / `client.ovpn` 由模板生成，证书内联进客户端配置

## API 契约

所有接口统一挂在 **`/api/v1`** 前缀下，例如：

```
POST /api/v1/logincheck
GET  /api/v1/account/userlist
GET  /api/v1/system/getBrand
```

- 响应统一为 `{"code":1,"msg":"...","data":...}`，`code` 非 1 即失败；`401` 未登录、`402` 试用到期未激活。
- 认证：HttpOnly Cookie（`sslvpn_session`）或 `Authorization: Bearer <token>` 二选一。
- `/api/v1` 的响应会带 `X-API-Version: v1` 头，便于客户端做版本探测。
- 前缀常量：后端 `handler.APIPrefix`（`internal/handler/routes.go`），前端 `API_BASE`（`webfs/dist/app.js`），改一处即可整体迁移。

**旧路径兼容**：`/logincheck`（裸路径）与 `/api/logincheck` 默认仍作为别名可用，
方便已有脚本/书签平滑过渡。彻底收敛只需加环境变量：

```yaml
# docker-compose.yml
environment:
  - SSLVPN_API_LEGACY_ALIAS=0   # 关闭旧前缀别名，仅保留 /api/v1
```

关闭后访问旧路径会返回 `{"code":0,"msg":"接口不存在（请使用 /api/v1 前缀）"}`，不会再落到 SPA 首页。

## 桌面客户端（Windows / macOS）

服务端下载页：**`https://<服务器地址>:58443/downloads`**。是否出现下载按钮、以及谁可以下载，由后台
「系统设置 → 客户端下载」统一控制（见下方「客户端下载管控」）。安装包放在 `deploy/downloads/`，
构建镜像时复制进 `/opt/sslvpn-client/` 作为内置兜底；管理员可在后台单独上传 Windows / macOS 包，
文件写入卷内 `/var/lib/sslvpn/downloads/`（重建容器不丢），上传了某平台的包就自动替换该平台的内置包。

> **本仓库不含安装包二进制**：`deploy/downloads/*.exe`、`*.pkg` 已由 `.gitignore` 排除（体积大，
> 且安装包内嵌网关地址）。从源码构建的镜像默认没有内置包，下载页会提示暂无可用文件；把安装包
> 放进 `deploy/downloads/` 后重新 `docker compose up -d --build`，或直接在后台「上传安装包」上传即可。
> 下表的文件名是客户端产物的命名约定，供对照使用。

| 文件 | 平台 | 说明 |
|---|---|---|
| `KSVPN-Setup-v0.4.3.exe` | Windows | 全量安装包（KSVPN 图标、标题与产品名，内嵌 `OpenVPN-2.7.8-I002-amd64.msi`；飞书扫码 / 本地 / LDAP 登录、自动下载配置、显示 VPN IP、断开按钮、DPAPI 记住密码；点右上角 X 直接断开 VPN 并退出；应用内头部为白色 KS＋透明背景 logo，安装脚本与 `%LOCALAPPDATA%\KSVPN` 路径全部为 KSVPN） |
| `configure-gateway.ps1` | Windows | 网关配置脚本；下载时由服务端按「全局设置 → 公网地址」实时生成，域名与端口自动跟随，无需手工修改或重新打包 |
| `KSVPN-macOS13-arm64-Full-v0.5.0.pkg` | macOS | **最新 v0.5.0**（应用名已统一为 `KSVPN.app`，安装时自动移除早期版本应用）全量安装包：Apple Silicon / macOS 13+，内置独立 OpenVPN **2.7.8** 引擎（取自 Tunnelblick 10.0.1 build 6570，OpenSSL 3.5.9）+ 特权后台服务，不依赖 Homebrew / Tunnelblick；支持本地账号 / LDAP / TOTP 动态码与飞书扫码登录，内置网关指向本服务器 |
| `KSVPN-macOS-Source-v1.0.0.zip` | macOS | SwiftUI 原生客户端源码包，在 Mac 上 `bash build-macos.sh` 生成 `.app`；支持 `gateway.txt` 自定义网关，作为换服务器备选 |
| `KSVPN-Windows-Uninstall.zip` | Windows | 卸载工具（仅管理员可见）：`Uninstall-KSVPN.cmd` + `KSVPN-uninstall.ps1` + 卸载说明 |
| `KSVPN-macOS-Uninstall.zip` | macOS | 卸载工具（仅管理员可见）：`KSVPN-Uninstall.command` + 卸载说明 |

> `KSVPN-macOS13-arm64-Full-v0.5.0.pkg` SHA256：
> `351fe2a7a0e81743f5792d29339887875f4c876d11c7e21822e3b15b0d7859e1`

### 客户端下载管控

后台「系统设置 → 客户端下载」集中控制下载开关、可见范围与安装包：

| 设置 | 默认值 | 效果 |
|---|---|---|
| 开放下载 | 开启 | 关闭后 `/downloads` 只显示「客户端下载暂未开放」，**不渲染任何下载按钮**；直接访问 `/downloads/<文件>` 同样返回 403 |
| 可见范围 | 仅管理员登录后下载 | 切成「免登录公开下载」后终端用户无需登录即可下载。管理员登录态复用后台的 `sslvpn_session` cookie，同源自动携带 |
| 上传安装包 | — | Windows（`.exe` / `.msi`）、macOS（`.pkg` / `.dmg` / `.zip`）分开上传，落在卷内 `/var/lib/sslvpn/downloads/`，重建容器不丢 |

**按访问系统自动筛选**：`/downloads` 依据 `User-Agent` 判断 Windows / macOS，主区只显示该系统对应的安装包
（可双击安装的 `.exe` / `.pkg` 排在首位），其它平台收入「为其它系统下载」折叠区；「首次使用必读」同步只显示本平台说明。
页面顶部提供「我是 macOS 用户 → / 我是 Windows 用户 → / 查看全部」切换，也可直接用
`?platform=windows` / `?platform=macos` / `?platform=all` 手工指定（便于管理员代下或 UA 误判）。
手机、Linux 等未识别系统显示全部并给出平台入口，不会把人挡在门外。
登录首页有「⬇ 客户端下载」入口，点击后跳转 `/downloads`，同样按 UA 自动筛选。
后台「当前可下载文件」管理列表**始终显示全部文件**，不受筛选影响；筛选只控制展示，
**不绕过**下载开关与登录门禁，直接访问 `/downloads/<文件>` 仍走同一套校验。

**内置包版本去重**：镜像内置目录若因增量解包残留多个版本的同平台安装包（如 v0.4.6 与 v0.5.0 并存），
下载页只显示文件名 `vX.Y.Z` 版本号最高的那个，被取代的旧版本不再列出；无版本号的辅助文件不受影响。

**源码包仅管理员可见**：SwiftUI 源码包（`macos-source`）只对已登录管理员展示，匿名用户在页面
（含折叠区）看不到，直链访问返回 403；与下载页整体「开放范围」设置独立生效。

**卸载工具（仅管理员可见）**：两个 `KSVPN-*-Uninstall.zip` 与源码包共用同一套单文件门禁
（`adminOnlyDownload()`）——普通用户在 `/downloads` 看不到、直链返回 403，管理员在后台
「当前可下载文件」列表里能看到并带「🔒 仅管理员」标记。需要发给个人时，点该行的
「✉ 发送」输入邮箱即可：邮件自动附上脚本，并按平台生成**完整卸载教程**（Windows 的
`Uninstall-KSVPN.cmd` / `%LOCALAPPDATA%\KSVPN` / OpenVPN；macOS 的 `KSVPN-Uninstall.command` /
`pkgutil` / LaunchDaemon）。卸载邮件不放下载页链接，避免普通用户点开看不到文件而困惑。
卸载包通过 `downloadPlatformKey()` 返回空键，不参与同平台版本去重，因此不会和 macOS 源码包
互相挤掉，也不会被当作安装包随账号邮件群发。

**客户端卸载**：

- **Windows（新版安装包）**：`KSVPN-Setup-v0.4.3.exe` 安装时会写
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\KSVPN`，并在开始菜单放「卸载 KSVPN」，
  可直接从「设置 → 应用 → 已安装的应用」卸载。安装脚本同时把卸载脚本放进
  `%LOCALAPPDATA%\KSVPN\`，双击 `Uninstall-KSVPN.cmd` 也能卸载。
- **Windows（脚本）**：结束客户端 / OpenVPN 进程 → 删桌面与开始菜单快捷方式 → 删卸载注册表项 →
  删 `%LOCALAPPDATA%\KSVPN`（配置、证书、profile、记住的密码、日志）；脚本按
  `launch-hidden.vbs` 特征识别快捷方式和历史安装目录，不写死旧命名，也不会误删其它软件。
  脚本**不卸载 OpenVPN Community 2.7.8 / TAP 网卡**，需要彻底移除请到「应用」里卸载并重启。
- **macOS**：`KSVPN-Uninstall.command` 会先请求管理员密码，再用 `pkgutil --files` 按安装收据
  精确删除 `.app`、OpenVPN 引擎、`/Library/PrivilegedHelperTools` 下的 helper、
  `/Library/LaunchDaemons` 下的后台服务，然后清用户配置并 `pkgutil --forget`；旧版数据目录按
  `gateway.txt` / `profiles` / `client.json` 特征识别，不写死产品名。源码包 `.app` 方式安装的
  客户端也能清理。单独用 Homebrew 装的 `openvpn` 不受影响。
- 独立脚本源文件同时放在 `deploy/client-tools/`，可不经过下载页直接分发。

**覆盖与删除**：同名上传直接覆盖；不同名上传会自动删除该平台的旧上传包，保证列表里每平台只有一个包。
后台文件列表中「上传」来源的包可随时点「🗑 删除」，删除后自动恢复显示镜像内置的同平台包；内置包本身不可删也不会丢。
单文件上限 300MB，文件名走白名单校验（拒绝路径穿越与非安装包扩展名）。

**✉ 邮件发送安装包**：后台文件列表每行提供「✉ 发送」，输入用户邮箱即可把该安装包（内置、上传或
动态生成的网关脚本）作为附件发出；需先在「系统设置 → 邮件服务」配置 SMTP，附件上限 20MB。
用户账号页「邮件」（含批量发送）的附带内容由「系统设置 → 客户端下载 → ✉ 账号邮件附件」开关控制：
**默认关闭，只发 VPN 配置文件**（历史行为）；开启后可勾选附带 VPN 配置文件 / Windows 客户端 /
macOS 客户端（客户端安装包自动取该平台版本最高者，上传包优先）——客户端发送可以不带配置文件。

**换网关不用重新打包**：`configure-gateway.ps1` 不再是镜像里的静态文件，而是下载时由后端按
「全局设置 → 服务器公网地址」实时生成（域名与端口自动跟随；公网地址未写端口且同主机访问时自动补当前端口）。
换服务器或改端口后，让用户重新下载一次该脚本即可，**Windows 安装包不需要重新打包或重新上传**。

**兼容性**：客户端调用的 `/api/v1/device/start`、`/device/poll`、`/profile/feishu`、`/profile/account`
与当前 Go 版完全一致，只要把网关基地址指向本服务器即可。网关写法 `https://域名:58443`，
**不要**带旧网关的 `/feishu-sso` 后缀。

**Windows 使用顺序**：运行安装包（自带 OpenVPN 2.7.8，无需另装）
→ 运行 `configure-gateway.ps1`（脚本由下载页自动生成，网关跟随全局公网地址；也可传 `-Gateway` 覆盖）
→ 打开客户端，飞书扫码或填本地/LDAP 账号密码 → 自动下载个人 `.tgz` 配置并连接 → 显示 VPN IP → 「断开 VPN」。
客户端的网关输入框在界面上不暴露，值保存在 `%LOCALAPPDATA%\KSVPN\client.json`。

**macOS 使用顺序（全量包）**：双击 `.pkg` → 按提示授权安装后台服务 → 从「应用程序」打开「KSVPN」。
包内自带 2.7.8 OpenVPN 引擎与特权后台服务，无需 `brew install openvpn`。

> **关于 macOS 全量包 v0.5.0**：应用显示名与包标识已统一为 `KSVPN.app` /
> `tech.ksvpn.vpn.full`，安装器会自动移除早期版本的应用。系统级服务目录与
> LaunchDaemon 标识符仍沿用早期命名，用于保证从旧版本平滑升级、不破坏已签名的
> `cdhash` 校验；卸载工具通过 `pkgutil --files` 按安装收据反查这些路径，
> 因此不依赖任何固定命名。macOS 的 `.app` / `.pkg` 必须在 Mac 上编译与签名，
> Windows 侧无法产出或安全改写。

> **网关说明**：v0.5.0 已把当前服务器网关（`https://<全局公网地址>:58443`）编进主程序，装好即连。
> 换服务器 / 换域名 / 换端口时**无需重新打包**：写一行新地址到
> `~/Library/Application Support/KSVPN/gateway.txt` 即可覆盖。
> 客户端与特权后台服务通过 `cdhash`（`client-requirement.txt` / `helper-requirement.txt`）互相校验代码签名，
> `postinstall` 还会执行 `codesign --verify --deep --strict`，所以**不要**在非 Mac 环境直接改二进制重打包。
> 该 pkg 是内部测试版，未用 Apple Developer ID 签名/公证，首次打开需右键 → 打开。

**本地账号登录字段兼容**：v0.4.6 起 macOS 客户端把 `/api/v1/profile/account` 的密码字段命名为 `secret`
（旧客户端为 `password`），服务端两个键名都接受；TOTP 账号支持 `password,动态码` 逗号格式
（与 OpenVPN auth-verify 行为一致），本地账号密码比对基于库内真实口令。

**登录方式（短账号 / 邮箱 / UPN·DN，推荐）**：默认**只允许短账号登录**，管理员可在
「用户与权限 → LDAP 目录 → 登录方式」按需开启另两种方式，三种可并存：

| 登录方式 | 开关 | 登录名来源 | 默认 |
|---|---|---|---|
| 短账号 | 固定开启，不可关闭 | `account.username` | 开 |
| 邮箱账号 | 邮箱账号 | `account.email`（唯一命中才放行） | 关 |
| UPN / DN | UPN / DN | `account.login_aliases`（逗号分隔，逐账号配置） | 关 |

别名在服务端解析成真实 VPN 用户名后，再查账号、绑定 LDAP、下发配置；
`/api/v1/profile/account` 与 OpenVPN `auth-verify` 共用 `vpn.ResolveLoginName()`，
因此 **LDAP 搜索过滤器保持 `(uid=%s)` 不用改，客户端也无需更新**。
短账号与 DN 常无字符串对应关系（如 `zhangsan` ↔ `zhangsan@example.com`），
系统**不做前缀推导**，必须在「用户账号 → 添加/编辑用户 → 登录别名」显式填写。
多个账号共用同一联系邮箱时，邮箱方式会因歧义拒绝登录；显式别名优先于邮箱匹配，
可绕开该歧义。禁用账号、未开启的方式、含 LDAP filter 元字符的输入一律拒绝。

**LDAP 搜索过滤器（另一种路线：直接把邮箱当 VPN 用户名）**：服务端只有一条 LDAP 校验链路，
账号形态由「搜索过滤器」决定，代码不区分 AD 与邮箱：

| 账号形态 | 搜索过滤器 | 账号示例 |
|---|---|---|
| AD 域短账号 | `(sAMAccountName=%s)` | `zhangsan` |
| 邮箱账号 | `(mail=%s)` | `zhangsan@example.com` |
| UPN 账号 | `(userPrincipalName=%s)` | `zhangsan@ad.example.com` |
| 通用 LDAP | `(uid=%s)`（默认） | `zhangsan` |

改过滤器后必须点「同步用户」重新导入（同步时 VPN 用户名取自过滤器属性），且已有短名账号不会自动改名、
短名会被 `(mail=短名)` 查不到而失效。**多数场景应改用上方「登录方式」开关，不要动过滤器。**
后台用户列表里的「联系邮箱」只是发邮件用，不是登录账号。用户同步写入的邮箱属性固定取 LDAP 的 `mail`，
没有独立的「邮箱属性映射」配置项。`@` 之外的 LDAP filter 元字符仍被禁止，避免注入。

**TOTP 与「记住密码」**：动态码 30 秒即失效，勾选记住密码时客户端只保存逗号前的静态密码，
下次登录需在密码框补 `,6位动态码`；普通账号仍按原样保存整串密码。

**应用内 logo**：Windows 客户端头部使用「白色 KS＋透明背景」（`ksvpn-icon.png`），与深色品牌面板融合；
exe 图标、桌面快捷方式与托盘图标仍用「白色 KS＋黑色圆角方形」（`KSVPN.ico`），保证浅色桌面与任务栏下可辨识。
`deploy/downloads/KSVPN-transparent.ico` 另附透明版备用素材。

**源码包路线**：安装 Xcode Command Line Tools 与 `brew install openvpn` → 解压源码包 →
`bash build-macos.sh` → 把 `build/KSVPN.app` 拖进「应用程序」。换服务器时无需重新编译，
写一行地址到 `~/Library/Application Support/KSVPN/gateway.txt` 即可覆盖默认值。

> **构建限制**：macOS 的 `.app` / `.pkg` 必须在 macOS 上编译与签名，Windows 本机无法产出或安全改写。
> 对外分发请用 Apple Developer ID 签名并公证；若需要 CI 自动出双平台包，可加 GitHub Actions 的
> `macos-latest` runner。

## 扫码登录（飞书 / 钉钉 / 企业微信）

内置飞书 / 钉钉 / 企业微信三种扫码登录渠道，全部由 `sslvpn-go` 单进程完成，
无需额外部署 Node 网关或 nginx 配置。

**链路（三渠道通用）**

```
POST /api/v1/device/start     → {provider, device_code, device_verifier, auth_url, expires_in, interval}
GET  /sso/auth/start          → 302 到对应渠道的授权页（按 device_code 取 state）
GET  /sso/callback            → 换 token → 取用户信息 → 映射账号 → 签发一次性口令
POST /api/v1/device/poll      → {status:"authorized", username, vpn_token:"FS1.xxxx"}
POST /api/v1/profile/feishu   → 凭 device_verifier 免密下载个人配置（.tgz，一次有效）
POST /api/v1/token/verify     → 服务间校验（Bearer 服务校验密钥，兼容旧脚本）
GET  /healthz                 → 健康检查
```

> `/device/start` 的 body 可带 `{"provider":"feishu|dingtalk|wecom"}`；不传则用管理端设置的「默认渠道」。
> 旧路径 `/feishu-sso/auth/start`、`/feishu-sso/callback`、`/auth/start`、`/callback` 保留为别名，已登记的
> redirect_uri 不需要改。

**口令核销**：`FS1.<base64url>` 直接填进 OpenVPN 的「密码」位，由 `sslvpn auth-verify` 在本地
SQLite 中原子核销（`consumed=0 → 1`），默认 60 秒有效、仅一次、与账号绑定；重放/过期/跨账号均拒绝并记入认证日志。

**各渠道差异**

| 渠道 | 凭证 | 需要的权限 / 配置 | 身份来源 |
|---|---|---|---|
| 飞书 | App ID + App Secret | `contact:user.email:readonly`；重定向 URL `…/callback` | `union_id/open_id` + 企业邮箱 |
| 钉钉 | AppKey + AppSecret | 「通讯录个人信息读权限」；回调域名 `…/callback` | `unionId/openId` + 邮箱 |
| 企业微信 | CorpID + AgentId + Secret | 自建应用的「企业微信授权登录 → Web 网页授权」可信域名 | `userid`（直接当账号名）+ `biz_mail` |

**身份映射顺序**（命中即返回）：渠道直给账号名（企微 `userid`）→ 本地扫码类账号按邮箱直配 →
LDAP 按 `carLicense` 等属性匹配渠道 ID（兼容 `feishu_` 前缀写法）→ LDAP 按 `mail` 匹配。
命中后统一校验：账号存在、启用、未过期、`auth_type ∈ {ldap, feishu, sso, dingtalk, wecom}`，以及可选的
`expected_username` 一致性。邮箱域名白名单、飞书租户 Key 在回调阶段校验。

**配置**：管理端「系统设置 → 扫码登录」，三个标签页分别填凭证，可同时启用多个渠道并指定默认渠道。
回调地址统一为 `https://<域名>/sso/callback`（也接受 `<域名>/feishu-sso/callback`）。
打开「联调模式」（全局或单渠道）可在不调用第三方接口的情况下用 `?mock_email=` / `?mock_login=` 跑通全流程。

**回调地址与全局公网地址联动**：飞书 / 钉钉 / 企业微信共用同一个回调基地址。扫码登录页的
「回调基地址」**留空**时，跟随「全局设置 → 服务器公网地址」自动变化，**域名和端口一起联动**
（公网地址没写端口、而管理页又是通过同一主机名的带端口地址访问时，会自动补上当前端口）；
页面顶部与各渠道提示里显示的 `<base>/callback` 会一起刷新。
旧版本会把自动推导值回填进输入框，一点「保存全部」就把它写死；现在保存与推导值相同的地址会视为留空，
历史配置重新保存一次即可恢复联动，也可点「↺ 跟随全局」清空。只有显式填了不同地址才固定不变。
授权页 `/sso/auth/start` 始终用纯域名（不带 `/feishu-sso` 前缀）拼接。
改完公网地址后，记得同步修改三个开放平台里登记的重定向 URL。

## 域名分流（按域名决定哪些流量走 VPN）

管理端「连接管理 → 域名分流」。**OpenVPN 的路由只认 IP**（`push "route <net> <mask>"`），不支持按域名选路，
所以这里的实现是：后台填域名 → 服务端定时解析成 IPv4 → 以 `/32` 主机路由写进 CCD 下发。只有这些 IP 走 VPN，
其余流量仍走本地网络（等价于「部分域名走 VPN」）。

**默认按用户下发，不需要重启实例**：路由写进该用户的 `ccd/<用户名>` 文件，OpenVPN 在客户端连接时才读 CCD，
所以改规则、改解析结果、加删域名 **只重写文件**，用户重新连接 VPN（或客户端自动重连）即生效。

| 能力 | 说明 |
|---|---|
| 下发对象 | **按用户**（默认，写 CCD，重连生效）；一个域名可同时给多个用户，一个用户可配多个域名 |
| 生效范围 | 全部实例或指定实例；限定实例时只写该实例的 CCD 文件 |
| 解析周期 | 每条规则独立 TTL，默认 300 秒；后台每分钟检查一次到期规则，IP 变化后自动重写相关 CCD |
| 不重启 | 用户维度规则**永不触发实例重启**；同步 CCD 只是文件写入 |
| 实例级（可选） | 规则不指定用户时写 `server.conf` 全局 push，对所有人生效，但需点「重启实例」 |
| 端口维度 | 不区分端口（L3 路由）；需要按端口限制请配合「访问控制」的 iptables 规则 |
| 依赖 | 只需要 DNS 可达；不依赖客户端安装任何插件 |

**为什么能"不重启"**：`server.conf` 的全局 `push` 在实例启动时定型，改它必须重载进程；而 `ccd/<user>` 是
每个客户端连接时按需读取的文件。把路由放进 CCD，就变成"改动即文件，生效靠重连"。

**限制（务必先读）**

- 用户**当前已连接的会话不会实时变更**——OpenVPN 不在线修改已下发的路由，需要用户重连（客户端断线重连即可）。
- CDN / 负载均衡类域名每次解析到的 IP 集合都不同，`/32` 路由会越积越散，这类场景请直接用「推送路由」配网段。
- 只有 AAAA（IPv6）记录的域名无法分流，后台会明确报错。
- 通配符（`*.example.com`）不支持，只能填具体主机名。
- 手工改过 `ccd/<用户名>` 文件的话，下一次域名解析刷新会被系统重写（以管理端 CCD 配置 + 域名规则为准）。

相关接口：`/api/v1/domainRoute/{list,add,update,delete,resolve,apply}`。
`domain_route` 表存 `service_id + username + domain`（`username` 为空表示实例级），以及上次解析的 IP、时间、TTL 与错误信息。

## 全局代理 vs 分流（「全局代理」勾选框的确切含义）

服务实例的「全局代理」复选框决定该实例下发的**默认**行为，两种模式互斥：

| | 勾选「全局代理」 | 不勾选（分流） |
|---|---|---|
| 路由 | `push "redirect-gateway def1 bypass-dhcp"`，客户端默认路由改走 VPN | 只 push「推送路由」+「域名分流」解析出的 `/32` |
| DNS | push 全局设置的 DNS1/DNS2（`dhcp-option DNS`） | **不推送 DNS**，解析交给客户端本地网络 |
| 其余流量 | 全部走 VPN | 走本地网络（家庭/公司原有出口） |
| 典型场景 | 出差/居家访问内网全部资源、隐藏真实出口 IP | 只把内网网段与指定域名送回公司，其余正常上网 |

要点：

- **分流模式下不推 DNS 是有意的**：若仍推 DNS，查询会发到 223.5.5.5 之类公网 DNS 再经隧道绕一圈，
  既拖慢解析，也让"其余走本地"失去意义。内网域名靠「域名分流」由**服务端**解析成 IP 下发，
  客户端无需能解析内网域名（前提：服务器本身能解析这些域名）。
- 个别用户若确需专用 DNS（例如内网 DNS），在「用户 → CCD/高级」里给该用户单独填 DNS，或选
  「全局代理」模式；用户级「全局代理」未填 DNS 时自动沿用全局设置的 DNS。
- 用户级还有「仅内网路由（忽略全局代理）」选项：对该用户 `push-reset`，实例的全局代理与 DNS 对它一律不生效。
- 改勾选后保存会自动重载实例，**在线用户需重连**才拿到新的路由/DNS。

## 证书自动续签（Let's Encrypt + 云 DNS）

「系统设置 → 证书管理」底部的**证书自动续签**面板：用 Let's Encrypt 免费证书 + 云 DNS 的
**DNS-01** 验证自动签发，到期前自动换新并热加载（不重启服务、不中断连接）。

**前置条件**

1. 域名的 NS **托管在所选云厂商**（阿里云 DNS / 腾讯云 DNSPod），且该域名已在对应账号下；
2. 云账号准备一对**子账号**凭证，只授权 DNS 解析的增删查权限（不要用主账号 AccessKey）；
3. 服务器时间准确（`ntpdate`/chrony 已同步），否则 ACME 验签会失败；
4. 服务器可以出网访问 `acme-v02.api.letsencrypt.org`。

**操作步骤**

1. 填「域名」（多个用逗号分隔，如 `vpn.example.com,www.example.com`，支持 `*.example.com`）；
2. 填「注册邮箱」（Let's Encrypt 到期通知 + ACME 账号注册用）；
3. 选 DNS 服务商，填 `AccessKeyId/SecretId` 与 `SecretKey`；
4. 点 **⚡ 测试 DNS 凭证**：会写一条临时 `_acme-challenge` TXT 再删除，验证权限与域名归属；
5. 点 **⚡ 立即签发**（约 1-3 分钟，等 DNS 生效），状态栏会显示结果与到期时间；
6. 勾选 **启用自动续签** → 保存。后台每 6 小时巡检一次，剩余天数 ≤「提前天数」（默认 30）自动续签。

**泛域名（通配符）**

- `*.example.com` **可以**自动签发——通配符证书只支持 DNS-01 验证，本模块正好走这条路；
- 通配符只覆盖**一级**子域：`*.example.com` 含 `a.example.com`，不含 `a.b.example.com`；
- `example.com` 与 `*.example.com` 是两个不同的证书名，需要同时覆盖就两个都填；
- 泛域名与主域同证书时，TXT 记录都在 `_acme-challenge.example.com` 下，lego 会自动处理多条记录。

**状态说明**

- 「当前证书」的来源标签由签发/上传动作写入并按签发机构复核：Let's Encrypt 的中间证书 CN 会轮换
  （`R3/E6/YE1/XR1`…），不会因 CN 变化把自动签发的证书误标成「手工上传」；
- 面板显示的到期时间是容器本地时间（镜像已设 `TZ=Asia/Shanghai`），与浏览器证书查看器一致；
- **修改「域名」后不会立刻重签**，需手动点一次「⚡ 立即签发」；自动续签到期触发时才会按新域名签发。

**凭证与文件位置**

| 内容 | 位置 | 说明 |
|---|---|---|
| 云 DNS 凭证 | SQLite `setting` 表（`cert_auto_ak/sk`） | AES-256-GCM 加密，密钥由 `session_secret` 派生；界面只回显打码值 |
| ACME 账号密钥 | `/var/lib/sslvpn/acme/account.key` | 更换服务器请一并备份，否则会重新注册账号 |
| 当前证书 | `/var/lib/sslvpn/ssl/server.crt|.key` | 续签时自动留 `.bak` 备份 |
| 最近一次结果 | `setting.cert_auto_last` | 界面「最近结果」读取 |

**到期提醒**：无论证书是自动签发还是手工上传，剩余 **15/7/3/1 天**时会给所有绑定了邮箱的
管理员发提醒邮件（需先配好「邮件服务」SMTP）；同一天同一剩余天数只发一次。

**限制与注意**

- Let's Encrypt 证书有效期 90 天；同一组域名**每周签发上限 5 次**，调试请勾选「使用 LE 测试环境」
  （签出的证书浏览器不信任，但流程完全一致、不占正式配额）；
- 域名解析必须已经指向本服务器（A/AAAA 记录），否则浏览器仍会报证书不匹配——DNS-01 只验证"域名归你"；
- 反向代理（Nginx/爱快）在前时，证书要装在**终止 TLS 的那一层**；本模块替换的是本程序 8443 的证书；
- 证书改变后旧客户端可能仍缓存会话，浏览器 `Ctrl+F5` 或重开窗口即可。

## 功能总览

| 模块 | 能力 |
|---|---|
| VPN 用户管理 | 增删改查、批量导入/删除、CSV 导出、过期禁用 |
| 认证方式 | 本地 / TOTP（RFC 6238 Go 实现）/ LDAP，`auth-verify` 读库校验 |
| 扫码登录 | 飞书 / 钉钉 / 企业微信三渠道，一次性口令本地核销，无外部依赖 |
| 路由 / 分流 | 网段推送 + **域名分流**（域名解析成 /32 路由写 CCD，按用户下发、重连即生效，不重启实例） |
| 证书体系 | easy-rsa batch 封装，签发/吊销/重建；支持 Let's Encrypt DNS-01 自动续签 |
| 多实例服务 | Go template 渲染配置 + 进程启停 + PID 兜底 |
| CCD 高级配置 | 每用户静态 IP/iroute/push，写入实例 ccd 目录 |
| 分组/服务关联 | 分组与实例关联管理 |
| 防火墙 | iptables 端口规则 + 按实例网段自动 SNAT |
| 上下线控制 | 钩子脚本由程序生成（CN 校验 + 单点在线） |
| 日志审计 | 访问日志、系统日志、在线状态、客户端 IP 汇总 |
| SMTP 邮件 | 开通通知/找回密码/发送安装包，465(SSL)/587(STARTTLS) 兼容 |
| 备份恢复 | tar.gz 备份/下载/上传 |
| 品牌自定义 | 「其它配置 → 品牌设置」上传 Logo（PNG/JPG/WEBP/GIF ≤512KB）+ 改名称，登录页/顶栏/浏览器标题/图标同步生效 |

## 目录结构

```
sslvpn-go/
├── docker-compose.yml        # NET_ADMIN + /dev/net/tun + ip_forward
├── Dockerfile                # 多阶段构建（golang:1.22 → debian:12 + openvpn）
├── deploy/entrypoint.sh      # tun 设备/路由转发/初始化/拉起实例
└── backend/
    ├── cmd/sslvpn/main.go    # 入口：init / auth-verify / 服务启动
    ├── internal/
    │   ├── db/               # SQLite 建表迁移
    │   ├── handler/          # 全部 API + 内嵌 LDAP 客户端
    │   ├── vpn/              # 实例管理/easy-rsa/TOTP/认证回调/CCD/状态解析
    │   ├── fw/               # iptables + SNAT
    │   ├── mail/             # SMTP
    │   ├── middleware/       # 会话(HMAC token) + CORS
    │   └── util/             # 统一响应/TOTP/随机
    └── webfs/dist/           # 内嵌中文管理前端（原生 JS SPA）
```

## 安全说明

- 管理员密码 bcrypt 存储；会话为 HMAC 签名 token（HttpOnly Cookie / Bearer 双支持）
- 登录失败 10 次锁定 10 分钟；算术图形验证码
- VPN 本地/TOTP 用户密码在库内为**明文或弱哈希**（因 OpenVPN `auth-user-pass-verify`
  via-file 机制需要可逆比对；TOTP 密钥本身即对称）——请确保数据库目录权限（容器内 0700），
  后续可升级为 HMAC challenge 方案
- 首次登录后请立即修改默认密码，并在「系统设置」中配置公网地址

## 忘记管理员密码怎么重置

管理员密码只以 bcrypt 哈希存库，**无法反查**，只能按下面两条路重置。

**方式一：网页找回（前提：该管理员绑了邮箱，且「系统设置 → 邮件服务」的 SMTP 已配通）**

登录页「忘记密码」→ 输入管理员邮箱 → 收 6 位安全码（10 分钟有效）→ 设新密码（≥8 位）。
SMTP 没配、邮箱填错或收不到信时走方式二。

**方式二：服务器上离线重置（推荐，不需要邮箱和 SMTP）**

```bash
# 1) 先看有哪些管理员（确认要重置的用户名，避免重置到普通运维账号）
docker exec -it sslvpn-go sslvpn reset-admin -list

# 2) 重置：不带参数 = 重置超级管理员并自动生成 16 位随机密码（终端会打印出来）
docker exec -it sslvpn-go sslvpn reset-admin

#    也可以指定用户名和密码（密码至少 8 位）
docker exec -it sslvpn-go sslvpn reset-admin -u admin -p 'MyNewPass2026'
```

命令说明：

- 直接改 `/var/lib/sslvpn/sslvpn.db`，不经过 Web，**容器运行中也能用**（SQLite WAL 多进程安全）。
- 重置时会顺手把该账号状态改回「启用」，并清掉它遗留的找回密码验证码。
- 忘记用户名时先用 `-list`；若 `-list` 显示没有任何管理员，执行
  `docker exec -it sslvpn-go sslvpn init` 会重建默认账号 `admin / ChangeMe`（已有管理员时不会覆盖）。

**重置后还登不上？两个常见原因**

```bash
# ① 该 IP 连续输错 10 次被锁 10 分钟；重启容器立即解锁（同时让已登录会话全部失效）
docker restart sslvpn-go

# ② 容器起不来、exec 不进去时，用一次性容器改卷里的库（镜像名与卷名取自现有容器，避免猜错）
IMG=$(docker inspect -f '{{.Config.Image}}' sslvpn-go)
docker run --rm -it -v "$(docker volume ls --format '{{.Name}}' | grep sslvpn-data | head -1)":/var/lib/sslvpn \
  --entrypoint sslvpn "$IMG" reset-admin
```

> 若容器已被删除，卷名通常是 `<compose 项目名>_sslvpn-data`；也可直接挂宿主机目录：
> `-v /你的路径/sslvpn:/var/lib/sslvpn`。

## 交付前检查清单（对外部署）

1. **改默认密码**：首次登录后立即修改 `admin / ChangeMe`。
2. **上传正式证书**：「证书管理」页替换自签证书，或在同页底部开启「证书自动续签」
   （Let's Encrypt + 阿里云/腾讯云 DNS，详见上文）。日志里 `TLS handshake error ... unknown certificate`
   即客户端不信任自签证书（浏览器未点"继续前往"时的正常告警），换正式证书后消失。
3. **明文 API 不外露**：`8080` 仅供容器内/反向代理调用，compose 默认已注释该映射。
4. **自定义端口**：管理页默认 8443（容器内固定 `SSLVPN_WEB_PORT`），宿主侧改映射即可，如
   `58443:8443`；VPN 端口改宿主映射（如 `51194:51194/udp`），或在「连接配置」里直接改实例
   监听端口（改后需重启实例并**重新下发客户端配置**，remote 行会随配置更新）。
5. **许可**：试用默认 15 天（`SSLVPN_TRIAL_DAYS`），对外交付记得用 `license-private.pem`
   离线签发许可；私钥不参与镜像构建，切勿放进交付包/客户服务器（本仓库位于 `deploy/keys/`，
   打交付包时请排除该文件，只保留签发出来的许可串）。
6. **防火墙**：只放行所需端口（本模板即 58443/tcp 与 51194/udp），数据库与 8080 不对外。
7. **数据备份**：`sslvpn-data`（SQLite/证书/CCD）与 `sslvpn-openvpn`（实例配置）两个卷需纳入备份。
8. **出交付包**：在项目根目录执行下列命令（务必排除签名私钥，且只带标准 compose）：

   ```bash
   tar -czf sslvpn-final.tar.gz \
     --exclude='deploy/keys/license-private.pem' \
     --exclude='deploy/keys/*.pem.bak' \
     --exclude='backend/sslvpn' --exclude='backend/sslvpn.exe' \
  Dockerfile README.md backend deploy docs docker-compose.yml
  ```

   打包后自查，下列命令应**无输出**：
   `tar -tzf sslvpn-final.tar.gz | grep -E 'license-private|private.*\.pem|nas\.yml'`。
   NAS / 群晖 / Unraid 的绑定目录模板由部署文档站单独提供，不随包分发。

## 捐赠与支持

KSVPN 以源码公开（Source Available）方式发布，长期维护需要持续投入。如果你的团队从中受益，欢迎扫码支持作者：
社区版为基础档，专业版与企业版用于换取更完善的授权、优先响应与定制支持。
完整在线版本见部署文档站「捐赠与支持」页面（含在线收款码与最新档位说明）。

### 版本与价格

| 档位 | 价格 | 包含功能 |
| --- | --- | --- |
| **社区版** Community | **¥39.9** / 基础授权 | 单实例核心 VPN：用户管理、本地密码 + TOTP；基础 push route / iroute、防火墙、日志审计；备份恢复、SMTP 邮件、品牌自定义；源码公开可审阅，生产使用需取得基础授权，含社区支持 |
| **专业版** Pro | **¥199** / 永久授权 | 包含社区版全部功能；域名分流、三渠道扫码登录（SSO）；CCD 高级配置、LDAP / AD 目录集成；官方桌面客户端分发与下载管控 |
| **企业版** Enterprise | **联系我** | 包含专业版全部功能；多实例 / 集群部署、私有化许可签发与在线登记；证书自动续签（ACME）、专属 SLA 与定制开发；合规、审计与培训支持 |

> 档位由许可的 `ed` / `ft` 字段决定，服务端按档位拦截高级接口，前端同步隐藏无权菜单
> （详见上文「授权与试用 → 版本档位」）。

### 扫码支持

可直接扫码付款，支持微信与支付宝；备注「专业版」可换取授权。

<table>
  <tr>
    <td align="center"><b>微信支付</b><br><img src="docs/pay/pay-wechat.jpg" width="220" alt="微信收款码"><br>打开微信「扫一扫」支持作者</td>
    <td align="center"><b>支付宝</b><br><img src="docs/pay/pay-alipay.jpg" width="220" alt="支付宝收款码"><br>打开支付宝「扫一扫」支持作者</td>
  </tr>
</table>

### 联系方式

| 渠道 | 账号 |
| --- | --- |
| QQ | `421381118` |
| 微信 | `WayneMiss` |
| 邮箱 | [421381118@qq.com](mailto:421381118@qq.com?subject=KSVPN%20授权咨询) |
| 官方 QQ 交流群 | `KS-SSLVPN`（群号 **897907129**，在 QQ 中搜索群号即可申请加入） |

### 下载与源码

国内用户建议从 Gitee 获取（无需代理、速度快），GitHub 为同步镜像，两端内容一致。

- [Gitee Releases 下载发布版](https://gitee.com/KingStrongerGee/ssvpn/releases)
- [Gitee 查看源码与文档](https://gitee.com/KingStrongerGee/ssvpn)
- [GitHub Releases（备用）](https://github.com/kingstronger-ai/ssvpn/releases)
- [GitHub 源码（备用）](https://github.com/kingstronger-ai/ssvpn)

```bash
# 国内（推荐）
git clone https://gitee.com/KingStrongerGee/ssvpn.git sslvpn-go
cd sslvpn-go && docker compose up -d --build

# 或 GitHub
git clone https://github.com/kingstronger-ai/ssvpn.git sslvpn-go
```

> 克隆时务必把目录命名为 `sslvpn-go`：目录名决定 Docker Compose 项目名，进而决定挂载哪一组
> 数据卷；改名会挂到空卷，看起来像「数据全丢了」。
> Git 仓库不含 `deploy/downloads/` 下的桌面客户端安装包（体积较大，已被 `.gitignore` 排除），
> 完整交付请使用 Releases 的 tar.gz / zip 离线包，或在后台上传客户端包（会落入数据卷，重建不丢）。

## 开发

```bash
cd backend
go build ./... && go vet ./...
go run ./cmd/sslvpn init   # 本地初始化（需 easy-rsa 或预置 pki/ca.crt 跳过）
go run ./cmd/sslvpn        # 启动（环境变量可覆盖所有路径）
```

环境变量：`SSLVPN_DATA_DIR` `SSLVPN_OPENVPN_DIR` `SSLVPN_PKI_DIR` `SSLVPN_HOOK_DIR`
`SSLVPN_WEB_PORT` `SSLVPN_API_PORT` `SSLVPN_BIN_OPENVPN` `SSLVPN_BIN_EASYRSA` `SSLVPN_DB`

> 未经完整生产环境验证，上线前请在测试环境验证 OpenVPN 连通性、防火墙与客户端下发配置。
