package bot

import "strings"

// pageHead 是每一屏标题：custom emoji + 粗体名，不再用 ASCII 分隔线。
func pageHead(emoji, name string) string {
	return em(emoji) + "  <b>" + name + "</b>\n"
}

func card(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return "<blockquote>" + s + "</blockquote>"
}

func btnHome() btn { return btn{"« 主菜单", "menu"} }

func btnBack(target string) btn { return btn{"« 返回", target} }
