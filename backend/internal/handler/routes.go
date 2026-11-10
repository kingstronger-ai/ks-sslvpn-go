// Package handler API 路由与处理器
package handler

import (
	"net/http"
	"strings"
)

// APIPrefix 后端接口的统一路径前缀（对外契约）。
// 表中注册的是「基路径」（如 /logincheck），实际对外暴露为 /api/v1/logincheck。
// 旧前缀（裸路径、/api/xxx）由 main.go 按 SSLVPN_API_LEGACY_ALIAS 开关决定是否保留为别名。
const APIPrefix = "/api/v1"

// Route 单条路由
type Route struct {
	Method string
	Auth   bool // 是否需要登录（对齐原 check 中间件）
	H      http.HandlerFunc
}

// Routes 路由表：path -> route
var Routes = map[string]Route{}

func reg(method, path string, auth bool, h http.HandlerFunc) {
	Routes[path] = Route{Method: method, Auth: auth, H: h}
}

func init() {
	// ---- 公开（登录/注册/找回/轮询）----
	reg("POST", "/logincheck", false, LoginCheck)
	reg("GET", "/logout", false, Logout)
	reg("GET", "/captcha", false, Captcha)
	reg("POST", "/getSafeCode", false, GetSafeCode)
	reg("POST", "/checkCode", false, CheckCode)
	reg("GET", "/getFlag", false, GetFlag)
	reg("POST", "/getCodeByVpnUser", false, GetCodeByVpnUser)
	reg("POST", "/findVpnUserPasswd", false, FindVpnUserPasswd)
	reg("POST", "/getRegisterVpnUserCode", false, GetRegisterVpnUserCode)
	reg("POST", "/registerVpnUser", false, RegisterVpnUser)
	reg("POST", "/getRegisterCode", false, GetRegisterCode)
	reg("POST", "/register", false, RegisterAdmin)
	reg("GET", "/pollingTask", false, PollingTask)
	reg("GET", "/checkOnlineStatus", false, CheckOnlineStatus)
	reg("GET", "/downloadca", false, DownloadCA)

	// ---- VPN 用户管理 ----
	reg("GET", "/account/userlist", true, AccountList)
	reg("POST", "/account/add", true, AccountAdd)
	reg("POST", "/account/delete", true, AccountDelete)
	reg("POST", "/account/update", true, AccountUpdate)
	reg("POST", "/account/systeminfo", true, SystemInfo)
	reg("GET", "/account/systeminfo", true, SystemInfo)
	reg("POST", "/account/exportDatabase", true, AccountExport)
	reg("POST", "/account/createAuthorize", true, CreateAuthorize)
	reg("GET", "/account/disableVpnServer", true, DisableVPNServer)
	reg("POST", "/account/batchUpload", true, AccountBatchUpload)
	reg("POST", "/account/batchDelete", true, AccountBatchDelete)
	reg("GET", "/account/startThinkPHPQueue", true, StartQueue)
	reg("POST", "/account/downloadUserCfg", true, DownloadUserCfg)
	reg("POST", "/account/rebuild", true, RebuildUserCfg)
	reg("POST", "/account/sendMail", true, SendUserMail)
	reg("POST", "/account/showDetail", true, AccountDetail)
	reg("POST", "/account/downloadUserCert", true, DownloadUserCert)
	reg("POST", "/account/getGroupAttach", true, GroupAttach)
	reg("GET", "/account/batchSendMail", true, BatchSendMail)
	reg("GET", "/account/batchBuildUserFile", true, BatchBuildUserFile)

	// ---- 日志 ----
	reg("GET", "/log/status", true, LogStatus)
	reg("GET", "/log/access", true, LogAccess)
	reg("GET", "/log/clientip", true, LogClientIP)
	reg("GET", "/log/vpnserverlog", true, LogVPNServer)
	reg("GET", "/log/deleteAccessLogs", true, DeleteAccessLogs)
	reg("GET", "/log/downloadVpnServerLogs", true, DownloadVPNServerLogs)
	reg("GET", "/log/editFilterRule", true, EditFilterRule)
	reg("POST", "/log/updateFilter", true, UpdateFilter)
	reg("GET", "/log/showRouterTable", true, ShowRouterTable)
	reg("GET", "/syslog/list", true, SyslogList)
	reg("GET", "/syslog/truncate", true, SyslogTruncate)

	// ---- 管理员 ----
	reg("GET", "/admin/list", true, AdminList)
	reg("POST", "/admin/update", true, AdminUpdate)
	reg("POST", "/admin/updateUserAdmin", true, AdminUpdate)
	reg("POST", "/admin/delUser", true, AdminDelete)
	reg("POST", "/admin/addAccount", true, AdminAdd)

	// ---- 系统设置 ----
	reg("POST", "/system/updateLogin", true, SysUpdateLogin)
	reg("POST", "/system/updateEmail", true, SysUpdateEmail)
	reg("POST", "/system/sendTestMail", true, SysSendTestMail)
	reg("POST", "/system/testDbConnect", true, SysTestDB)
	reg("POST", "/system/updateMysql", true, SysTestDB)
	reg("POST", "/system/updateDebug", true, SysUpdateDebug)
	reg("POST", "/system/updateWebPort", true, SysUpdateWebPort)
	reg("POST", "/system/updateSecureCode", true, SysUpdateSecureCode)
	reg("POST", "/system/updateRegisterAdminStatus", true, SysUpdateRegAdmin)
	reg("POST", "/system/updateRegisterUserStatus", true, SysUpdateRegUser)
	reg("POST", "/system/updateDownloadUrl", true, SysUpdateDownloadURL)
	reg("POST", "/system/updateKeyFile", true, SysUpdateKeyFile)
	reg("GET", "/system/getKeyFile", true, SysGetKeyFile)
	// ---- 证书自动续签（Let's Encrypt + 阿里云/腾讯云 DNS）----
	reg("GET", "/cert/auto/get", true, CertAutoGet)
	reg("POST", "/cert/auto/save", true, CertAutoSave)
	reg("POST", "/cert/auto/test", true, CertAutoTestDNS)
	reg("POST", "/cert/auto/issue", true, CertAutoIssue)
	reg("GET", "/cert/auto/status", true, CertAutoStatus)
	reg("GET", "/system/rebootNginx", true, SysRebootWeb)
	reg("GET", "/system/backup", true, SysBackup)
	reg("GET", "/system/getBackupInfo", true, SysBackupInfo)
	reg("GET", "/system/getMailTemplate", true, MailTemplateGet)
	reg("POST", "/system/updateMailTemplate", true, MailTemplateUpdate)
	// ---- 品牌自定义（名称/Logo，登录页亦需读取故公开）----
	reg("GET", "/system/getBrand", false, BrandGet)
	reg("GET", "/brand/logo", false, BrandLogo)
	reg("POST", "/system/uploadLogo", true, BrandUpload)
	reg("POST", "/system/updateBrand", true, BrandUpdate)
	reg("POST", "/system/resetLogo", true, BrandReset)
	// ---- 授权管理 ----
	reg("GET", "/license/info", true, LicenseInfo)
	reg("POST", "/license/activate", true, LicenseActivate)
	reg("POST", "/license/clear", true, LicenseClear)
	reg("POST", "/system/downloadBackupFile", true, SysBackupDownload)
	reg("POST", "/system/deleteBackupFile", true, SysBackupDelete)
	reg("POST", "/system/submitUpload", true, SysBackupUpload)
	// ---- 客户端下载：开关 / 可见范围 / 单独上传 Windows、macOS 安装包 ----
	reg("GET", "/system/clientDownload/get", true, ClientDownloadConfigGet)
	reg("POST", "/system/clientDownload/save", true, ClientDownloadConfigSave)
	reg("POST", "/system/clientDownload/upload", true, ClientDownloadUpload)
	reg("POST", "/system/clientDownload/delete", true, ClientDownloadDelete)
	reg("POST", "/system/clientDownload/mail", true, ClientDownloadMail)
	reg("GET", "/system/loginAlias/get", true, LoginAliasGet)
	reg("POST", "/system/loginAlias/save", true, LoginAliasSave)
	reg("POST", "/system/submitSysName", true, SysUpdateName)
	reg("POST", "/system/updateLoginEmail", true, SysUpdateEmail)
	reg("POST", "/system/updateCopyright", true, SysUpdateCopyright)
	reg("POST", "/system/submitUpdateSystem", true, SysUpdateSystem)
	reg("GET", "/system/getLoginOp", true, SysGetLoginOp)
	reg("GET", "/system/getRegisterList", true, SysGetRegisterList)
	reg("GET", "/system/getCertList", true, SysGetCertList)
	reg("GET", "/system/getOtherInfo", true, SysGetOtherInfo)
	reg("GET", "/system/getSmtpInfo", true, SysGetSMTP)

	// ---- CCD ----
	reg("GET", "/ccd/", true, CcdList)
	reg("GET", "/ccd/userlist", true, CcdUserList)
	reg("POST", "/ccd/addccdCfg", true, CcdAdd)
	reg("DELETE", "/ccd/remove", true, CcdRemove)
	reg("POST", "/ccd/update", true, CcdUpdate)
	reg("GET", "/ccd/getAllUser", true, CcdAllUser)
	reg("POST", "/ccd/copySubmit", true, CcdCopy)
	reg("POST", "/ccd/batchDeleteCcd", true, CcdBatchDelete)
	reg("POST", "/ccd/getServiceInCcd", true, CcdServiceIn)

	// ---- 分组 ----
	reg("GET", "/group/list", true, GroupList)
	reg("POST", "/group/addGroup", true, GroupAdd)
	reg("POST", "/group/removeGroup", true, GroupRemove)
	reg("POST", "/group/update", true, GroupUpdate)

	// ---- 服务实例 ----
	reg("POST", "/service/add", true, ServiceAdd)
	reg("GET", "/service/list", true, ServiceList)
	reg("POST", "/service/stop", true, ServiceStop)
	reg("POST", "/service/start", true, ServiceStart)
	reg("GET", "/service/getServiceAndGroups", true, ServiceAndGroups)
	reg("POST", "/service/submit", true, ServiceAttachGroup)
	reg("POST", "/service/cancelAttach", true, ServiceCancelAttach)
	reg("POST", "/service/addRouter", true, ServiceAddRouter)
	reg("POST", "/service/removeRouter", true, ServiceRemoveRouter)
	reg("POST", "/service/removeService", true, ServiceRemove)
	reg("POST", "/service/editService", true, ServiceEdit)
	reg("POST", "/service/clearlog", true, ServiceClearLog)
	reg("POST", "/service/downloadlog", true, ServiceDownloadLog)
	reg("GET", "/service/stopAllService", true, ServiceStopAll)
	reg("POST", "/service/getServiceConfiguration", true, ServiceConfiguration)
	reg("GET", "/service/getServiceTemplateCfg", true, ServiceTemplateCfg)
	reg("POST", "/service/updateServiceTemplateCfg", true, ServiceUpdateTemplateCfg)
	reg("GET", "/service/getClientTemplateCfg", true, ServiceClientTemplateCfg)
	reg("POST", "/service/updateClientTemplateCfg", true, ServiceUpdateClientTemplateCfg)

	// ---- 全局配置 / 防火墙 / LDAP / 授权 ----
	reg("GET", "/linuxcc/get", true, GlobalCfgGet)
	reg("POST", "/linuxcc/update", true, GlobalCfgUpdate)
	reg("GET", "/fw/getPortRuleList", true, FWRuleList)
	reg("POST", "/fw/addPortRule", true, FWAddRule)

	// ---- 域名分流（域名 → 定时解析 IPv4 → /32 路由下发）----
	reg("GET", "/domainRoute/list", true, DomainRouteList)
	reg("POST", "/domainRoute/add", true, DomainRouteAdd)
	reg("POST", "/domainRoute/addMulti", true, DomainRouteAddMulti)
	reg("POST", "/domainRoute/update", true, DomainRouteUpdate)
	reg("POST", "/domainRoute/delete", true, DomainRouteDelete)
	reg("POST", "/domainRoute/resolve", true, DomainRouteResolve)
	reg("POST", "/domainRoute/apply", true, DomainRouteApply)
	reg("GET", "/ldap/get", true, LdapGet)
	reg("GET", "/ldap/set", true, LdapSet)
	reg("GET", "/ldap/listusers", true, LdapListUsers)
	reg("GET", "/ldap/ping", true, LdapPing)
	reg("POST", "/ldap/test", true, LdapTest)
	reg("GET", "/ldap/synchronization", true, LdapSync)
	reg("POST", "/ldap/import", true, LdapImport)
	reg("POST", "/ldap/update", true, LdapUpdate)
	reg("GET", "/license/accept", true, LicenseAccept)

	// ---- 飞书扫码登录（公开：客户端与浏览器直接访问，内部各自校验）----
	// 对外路径即 /api/v1/device/start、/api/v1/device/poll、/api/v1/profile/feishu、
	// /api/v1/profile/account、/api/v1/token/verify（与既有客户端/网关脚本保持一致；
	// profile/account 的密码字段同时接受 password 与 secret，兼容 v0.4.6+ macOS 客户端）。
	reg("POST", "/device/start", false, SSODeviceStart)
	reg("POST", "/device/poll", false, SSODevicePoll)
	reg("POST", "/profile/feishu", false, SSOProfile)
	reg("POST", "/profile/account", false, LDAPProfile)
	reg("POST", "/token/verify", false, SSOTokenVerify)
	// 管理端配置
	reg("GET", "/system/getFeishu", true, SSOCfgGet)
	reg("POST", "/system/updateFeishu", true, SSOCfgSave)
	reg("POST", "/system/testFeishu", true, SSOTest)
}

// APIPath 把路由表里的基路径拼成对外完整路径，如 /logincheck -> /api/v1/logincheck
func APIPath(base string) string {
	if base == "" || base == "/" {
		return APIPrefix + "/"
	}
	if strings.HasPrefix(base, APIPrefix+"/") {
		return base
	}
	return APIPrefix + base
}

// BasePath 去掉已知的 API 前缀，还原为路由表里的基路径（日志、白名单判定用）
func BasePath(p string) string {
	for _, pre := range []string{APIPrefix, "/api"} {
		if p == pre {
			return "/"
		}
		if strings.HasPrefix(p, pre+"/") {
			return strings.TrimPrefix(p, pre)
		}
	}
	return p
}
