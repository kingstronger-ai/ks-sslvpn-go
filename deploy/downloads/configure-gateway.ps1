#requires -Version 5.1
<#
  占位文件：服务器下载页 /downloads 会在用户下载 configure-gateway.ps1 时，
  按「全局设置 → 服务器公网地址」实时注入网关地址并生成完整脚本。
  本文件不会被直接下载，请勿从镜像目录里直接拷贝使用；
  需要网关配置脚本时，一律从 https://<服务器地址>:58443/downloads 重新下载。
#>
throw "这是占位文件。请从服务器下载页 /downloads 重新下载 configure-gateway.ps1，服务端会自动写入当前网关地址。"
