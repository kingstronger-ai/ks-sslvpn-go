// Package handler API 路由与处理器
package handler

import (
	"net/http"
	"strings"

	"sslvpn/internal/license"
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

// regF 注册需要授权档位的接口：请求先过 gateFeature（未开启该功能返回 403 + 升级提示），
// 再进入原 handler。用于专业版 / 企业版功能的后端硬拦截。
func regF(method, path string, auth bool, feature string, h http.HandlerFunc) {
	reg(method, path, auth, func(w http.ResponseWriter, r *http.Request) {
		if !gateFeature(w, feature) {
			return
		}
		h(w, r)
	})
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
	// ---- 证书自动续签（Let's Encrypt + 阿里云/腾讯云 DNS）——企业版功能 ----
	regF("GET", "/cert/auto/get", true, license.FeatACMERenew, CertAutoGet)
	regF("POST", "/cert/auto/save", true, license.FeatACMERenew, CertAutoSave)
	regF("POST", "/cert/auto/test", true, license.FeatACMERenew, CertAutoTestDNS)
	regF("POST", "/cert/auto/issue", true, license.FeatACMERenew, CertAutoIssue)
	regF("GET", "/cert/auto/status", true, license.FeatACMERenew, CertAutoStatus)
	reg("GET", "/system/rebootNginx", true, SysRebootWeb)
	reg("GET", "/system/backup", true, SysBackup)

	// ---- 在线升级（检测/确认/状态/回滚；实际替换由宿主机代理执行）----
	reg("GET", "/upgrade/version", true, UpgradeVersion)
	reg("GET", "/upgrade/check", true, UpgradeCheck)
	reg("POST", "/upgrade/apply", true, UpgradeApply)
	reg("GET", "/upgrade/status", true, UpgradeStatus)
	reg("GET", "/upgrade/backups", true, UpgradeBackups)
	reg("GET", "/upgrade/log", true, UpgradeLog)
	reg("POST", "/upgrade/rollback", true, UpgradeRollback)
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
	// ---- 客户端下载：开关 / 可见范围 / 单独上传 Windows、macOS 安装包 —— 专业版功能 ----
	regF("GET", "/system/clientDownload/get", true, license.FeatClientDownload, ClientDownloadConfigGet)
	regF("POST", "/system/clientDownload/save", true, license.FeatClientDownload, ClientDownloadConfigSave)
	regF("POST", "/system/clientDownload/upload", true, license.FeatClientDownload, ClientDownloadUpload)
	regF("POST", "/system/clientDownload/delete", true, license.FeatClientDownload, ClientDownloadDelete)
	regF("POST", "/system/clientDownload/mail", true, license.FeatClientDownload, ClientDownloadMail)
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

	// ---- CCD —— 专业版功能 ----
	regF("GET", "/ccd/", true, license.FeatCCD, CcdList)
	regF("GET", "/ccd/userlist", true, license.FeatCCD, CcdUserList)
	regF("POST", "/ccd/addccdCfg", true, license.FeatCCD, CcdAdd)
	regF("DELETE", "/ccd/remove", true, license.FeatCCD, CcdRemove)
	regF("POST", "/ccd/update", true, license.FeatCCD, CcdUpdate)
	regF("GET", "/ccd/getAllUser", true, license.FeatCCD, CcdAllUser)
	regF("POST", "/ccd/copySubmit", true, license.FeatCCD, CcdCopy)
	regF("POST", "/ccd/batchDeleteCcd", true, license.FeatCCD, CcdBatchDelete)
	regF("POST", "/ccd/getServiceInCcd", true, license.FeatCCD, CcdServiceIn)

	// ---- 分组 ----
	reg("GET", "/group/list", true, GroupList)
	reg("POST", "/group/addGroup", true, GroupAdd)
	reg("POST", "/group/removeGroup", true, GroupRemove)
	reg("POST", "/group/update", true, GroupUpdate)

	// ---- 服务实例 ----（新增实例为企业版功能；既有实例的管理不受限）
	regF("POST", "/service/add", true, license.FeatMultiInstance, ServiceAdd)
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

	// ---- 域名分流（域名 → 定时解析 IPv4 → /32 路由下发）—— 专业版功能 ----
	regF("GET", "/domainRoute/list", true, license.FeatDomainRoute, DomainRouteList)
	regF("POST", "/domainRoute/add", true, license.FeatDomainRoute, DomainRouteAdd)
	regF("POST", "/domainRoute/addMulti", true, license.FeatDomainRoute, DomainRouteAddMulti)
	regF("POST", "/domainRoute/update", true, license.FeatDomainRoute, DomainRouteUpdate)
	regF("POST", "/domainRoute/delete", true, license.FeatDomainRoute, DomainRouteDelete)
	regF("POST", "/domainRoute/resolve", true, license.FeatDomainRoute, DomainRouteResolve)
	regF("POST", "/domainRoute/apply", true, license.FeatDomainRoute, DomainRouteApply)
	// ---- LDAP / AD 目录集成 —— 专业版功能（仅管理配置；客户端密码登录 /profile/account 不受限）----
	regF("GET", "/ldap/get", true, license.FeatLDAP, LdapGet)
	regF("GET", "/ldap/set", true, license.FeatLDAP, LdapSet)
	regF("GET", "/ldap/listusers", true, license.FeatLDAP, LdapListUsers)
	regF("GET", "/ldap/ping", true, license.FeatLDAP, LdapPing)
	regF("POST", "/ldap/test", true, license.FeatLDAP, LdapTest)
	regF("GET", "/ldap/synchronization", true, license.FeatLDAP, LdapSync)
	regF("POST", "/ldap/import", true, license.FeatLDAP, LdapImport)
	regF("POST", "/ldap/update", true, license.FeatLDAP, LdapUpdate)
	reg("GET", "/license/accept", true, LicenseAccept)

	// ---- 扫码登录（公开：客户端与浏览器直接访问，内部各自校验）—— 专业版功能 ----
	// 对外路径即 /api/v1/device/start、/api/v1/device/poll、/api/v1/profile/feishu、
	// /api/v1/token/verify（与既有客户端/网关脚本保持一致；
	// profile/account 的密码字段同时接受 password 与 secret，兼容 v0.4.6+ macOS 客户端，
	// 且该端点同时承载本地 / TOTP 账号登录，不按 SSO 拦截）。
	regF("POST", "/device/start", false, license.FeatSSO, SSODeviceStart)
	regF("POST", "/device/poll", false, license.FeatSSO, SSODevicePoll)
	regF("POST", "/profile/feishu", false, license.FeatSSO, SSOProfile)
	reg("POST", "/profile/account", false, LDAPProfile)
	regF("POST", "/token/verify", false, license.FeatSSO, SSOTokenVerify)
	// 管理端配置
	regF("GET", "/system/getFeishu", true, license.FeatSSO, SSOCfgGet)
	regF("POST", "/system/updateFeishu", true, license.FeatSSO, SSOCfgSave)
	regF("POST", "/system/testFeishu", true, license.FeatSSO, SSOTest)
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
