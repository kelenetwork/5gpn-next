// Package qrcode 生成描述文件下载链接的二维码 PNG。
package qrcode

import (
	"fmt"

	skipqr "github.com/skip2/go-qrcode"
)

// EncodePNG 把 content 编成白底黑码的 PNG，供 Telegram 下发。
func EncodePNG(content string) ([]byte, error) {
	if content == "" {
		return nil, fmt.Errorf("内容为空")
	}
	png, err := skipqr.Encode(content, skipqr.Medium, 320)
	if err != nil {
		return nil, fmt.Errorf("生成二维码失败: %w", err)
	}
	return png, nil
}
