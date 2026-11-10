// 品牌自定义：系统名称 + 自定义 Logo（登录页与内部界面共用）
package handler

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sslvpn/internal/db"
	"sslvpn/internal/util"
)

const defaultBrandName = "KSVPN"
const defaultCopyright = "© 2026-至今 Power by KingStronger"

// 允许的 Logo 格式（不接收 SVG：可内嵌脚本，同源加载存在 XSS 风险）
var logoExts = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".webp": "image/webp",
	".gif":  "image/gif",
}

func brandDir() string {
	d := os.Getenv("SSLVPN_BRAND_DIR")
	if d == "" {
		d = "/var/lib/sslvpn/brand"
	}
	return d
}

// findLogoFile 返回已上传的自定义 Logo 路径（无则空）
func findLogoFile() (string, string) {
	for ext, mime := range logoExts {
		p := filepath.Join(brandDir(), "logo"+ext)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			return p, mime
		}
	}
	return "", ""
}

// brandLogoURL 自定义 Logo 的访问地址（带版本参数避开浏览器缓存）
func brandLogoURL() string {
	if p, _ := findLogoFile(); p == "" {
		return "/logo.png"
	}
	v := db.GetSetting("brand_logo_ver")
	if v == "" {
		v = "1"
	}
	return APIPath("/brand/logo") + "?v=" + v
}

func brandName() string {
	if n := strings.TrimSpace(db.GetSetting("brand_name")); n != "" {
		return n
	}
	return defaultBrandName
}

// brandCopyright 底部版权文字（未设置时用默认）
func brandCopyright() string {
	if c := strings.TrimSpace(db.GetSetting("copyright")); c != "" {
		return c
	}
	return defaultCopyright
}

// BrandGet 公开接口：登录页渲染前需要拿到名称与 Logo
func BrandGet(w http.ResponseWriter, r *http.Request) {
	_, mime := findLogoFile()
	util.OK(w, map[string]any{
		"name":          brandName(),
		"logo_url":      brandLogoURL(),
		"custom_logo":   mime != "",
		"default_name":  defaultBrandName,
		"default_logo":  "/logo.png",
		"copyright":     brandCopyright(),
		"copyright_url": strings.TrimSpace(db.GetSetting("copyright_url")),
	})
}

// BrandLogo 公开接口：输出自定义 Logo 文件
func BrandLogo(w http.ResponseWriter, r *http.Request) {
	p, mime := findLogoFile()
	if p == "" {
		util.Fail(w, "未设置自定义 Logo")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		util.Fail(w, "Logo 读取失败")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = io.Copy(w, f)
}

// BrandUpload 上传自定义 Logo（multipart/form-data，字段名 file）
func BrandUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20) // 硬上限 4MB
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		util.Fail(w, "文件解析失败（限制 4MB）")
		return
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		util.Fail(w, "请选择图片文件")
		return
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(hdr.Filename))
	mime, ok := logoExts[ext]
	if !ok {
		util.Fail(w, "仅支持 PNG / JPG / WEBP / GIF 格式")
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		util.Fail(w, "文件读取失败")
		return
	}
	if len(data) > 512<<10 {
		util.Fail(w, "图片请小于 512KB")
		return
	}
	// 魔数校验，防止伪装扩展名
	if !sniffImage(data, mime) {
		util.Fail(w, "文件内容不是有效图片")
		return
	}

	dir := brandDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		util.Fail(w, "Logo 目录创建失败")
		return
	}
	// 清理旧格式文件
	for e := range logoExts {
		_ = os.Remove(filepath.Join(dir, "logo"+e))
	}
	dst := filepath.Join(dir, "logo"+ext)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		util.Fail(w, "Logo 保存失败")
		return
	}
	db.SetSetting("brand_logo_ver", time.Now().Format("20060102150405"))
	util.OKMsg(w, "Logo 已更新", map[string]string{"logo_url": brandLogoURL()})
}

// BrandUpdate 更新系统名称
func BrandUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := util.ReadJSON(r, &req); err != nil {
		util.Fail(w, "参数错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		util.Fail(w, "系统名称不能为空")
		return
	}
	if len([]rune(req.Name)) > 40 {
		util.Fail(w, "系统名称最多 40 个字符")
		return
	}
	db.SetSetting("brand_name", req.Name)
	db.SetSetting("sys_name", req.Name) // 与旧字段保持同步，系统信息页共用
	util.OKMsg(w, "系统名称已更新", map[string]string{"name": req.Name})
}

// BrandReset 恢复默认 Logo（不影响名称）
func BrandReset(w http.ResponseWriter, r *http.Request) {
	dir := brandDir()
	for e := range logoExts {
		_ = os.Remove(filepath.Join(dir, "logo"+e))
	}
	db.SetSetting("brand_logo_ver", "")
	util.OKMsg(w, "已恢复默认 Logo", map[string]string{"logo_url": "/logo.png"})
}

// sniffImage 通过文件头判断真实图片类型
func sniffImage(b []byte, mime string) bool {
	switch mime {
	case "image/png":
		return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n"))
	case "image/jpeg":
		return bytes.HasPrefix(b, []byte("\xff\xd8\xff"))
	case "image/gif":
		return bytes.HasPrefix(b, []byte("GIF8"))
	case "image/webp":
		return len(b) > 12 && bytes.HasPrefix(b, []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP"))
	}
	return false
}
