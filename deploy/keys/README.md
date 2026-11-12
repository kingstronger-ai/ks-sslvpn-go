# 签发密钥（请自备，本仓库不含私钥）

`license-private.pem` 是 **Ed25519 私钥**，用于签发授权许可。本仓库出于安全考虑**不包含私钥**，请将你自己的 `license-private.pem` 放在本目录后再执行下方命令。

## 使用方式

在**你自己的电脑**上（不要放到被授权的服务器上）：

```bash
# 方式一：不绑机器（推荐给对方，只需邮箱 + 公司名）
./sslvpn license-gen -bind none -email 421381118@qq.com -company "Your Company" -days 365 \
    -key license-private.pem

# 方式二：绑定机器（客户先发来机器码）
docker exec ks-sslvpn-go sslvpn license-info   # 在客户服务器上取机器码
./sslvpn license-gen -machine 908B-ADFD-D055-BFC0 -company "某某科技有限公司" -days 365 \
    -key license-private.pem

# 签发后自检（不需私钥）
./sslvpn license-inspect -token '<许可串>'

# 把输出的许可串整行发给客户，粘贴到「授权管理 → 激活许可」
```

> **许可编号**：默认从 **1** 开始自增，序号写入与私钥同目录的 `license.seq`（可用 `-seq-file`
> 指定位置）。签发机迁移时请一并备份该文件，避免编号重复；也可用 `-id` 显式指定编号。

浮动许可（`-bind none`）同时只允许 1 台机器激活：纯离线时靠"首次激活记录 + 原机解除激活"，
需要硬约束时启用 `sslvpn license-registry` 登记服务（详见主 README 的「授权与试用」）。

## 安全须知

- 私钥泄露 = 任何人都能签发许可。建议离线保存（U 盘 / 密码管理器）。
- 私钥**不参与镜像构建**，`docker compose build` 不会把它打进镜像。
- 若私钥泄露，需要重新生成密钥对并重新编译镜像（更换 `backend/internal/license/pub.pem`），
  旧许可全部失效。
- 绑定机器的许可换服务器需重新签发；浮动许可换机只需在原机解除激活。
