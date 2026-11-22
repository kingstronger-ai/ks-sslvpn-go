package handler

import (
	"net/http"

	"sslvpn/internal/alert"
	"sslvpn/internal/util"
)

func init() {
	// 告警配置均需登录；/alert/config 同路径 GET/POST 由 handler 内部分发（main.go apiEntry 用 "*" 放行方法）
	reg("*", "/alert/config", true, AlertConfigHandler)
	reg("POST", "/alert/test", true, AlertTestHandler)
	reg("GET", "/alert/history", true, AlertHistoryHandler)
}

// AlertConfigHandler GET 读取配置（URL 打码）；POST 校验并保存配置。
func AlertConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		c, err := alert.LoadConfig()
		if err != nil {
			util.Fail(w, err.Error())
			return
		}
		util.OK(w, alert.MaskConfig(c))
	case http.MethodPost:
		var c alert.Config
		if err := util.ReadJSON(r, &c); err != nil {
			util.Fail(w, "请求体解析失败："+err.Error())
			return
		}
		if err := alert.SaveConfig(c); err != nil {
			util.Fail(w, err.Error())
			return
		}
		util.OKMsg(w, "告警配置已保存", alert.MaskConfig(c))
	default:
		w.Header().Set("Allow", "GET, POST")
		util.FailStatus(w, http.StatusMethodNotAllowed, "该接口仅支持 GET/POST")
	}
}

// AlertTestHandler 向所有已配置渠道发送测试通知。
func AlertTestHandler(w http.ResponseWriter, r *http.Request) {
	results, err := alert.SendTest()
	if err != nil {
		util.Fail(w, err.Error())
		return
	}
	util.OK(w, results)
}

// AlertHistoryHandler 返回最近 50 条告警记录（内存存储）。
func AlertHistoryHandler(w http.ResponseWriter, r *http.Request) {
	util.OK(w, alert.History())
}
