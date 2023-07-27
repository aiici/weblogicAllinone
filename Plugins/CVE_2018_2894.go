package Plugins

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func isLive(ur string, port int) (int, int, error) {
	url1 := fmt.Sprintf("http://%s:%d/ws_utc/begin.do", ur, port)
	resp1, err := http.Get(url1)
	if err != nil {
		return 0, 0, err
	}
	defer resp1.Body.Close()

	url2 := fmt.Sprintf("http://%s:%d/ws_utc/config.do", ur, port)
	resp2, err := http.Get(url2)
	if err != nil {
		return 0, 0, err
	}
	defer resp2.Body.Close()

	return resp1.StatusCode, resp2.StatusCode, nil
}

func run2894(rip string, rport int) (int, string) {
	a, b, err := isLive(rip, rport)
	if err != nil {
		return 0, fmt.Sprintf("[-] [%s:%d] Error checking WebLogic: %v", rip, rport, err)
	}

	if a == 200 || b == 200 {
		return 1, fmt.Sprintf("[+] 存在漏洞 %s ", VUL[7])
	} else {
		return 0, fmt.Sprintf("[-] 已扫描 %s ", VUL[7])
	}
}

func Check2894() {
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
			_, resultMsg := run2894(targetHost, portInt)
			fmt.Println(resultMsg)
		}
	}
}
