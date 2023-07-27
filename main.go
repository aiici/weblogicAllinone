package main

import (
	"fmt"
	"os"
	"time"
	"weblogicAiiCi/Plugins"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <ip>")
		os.Exit(1)
	}
	targetIP := os.Args[1]
	fmt.Println("[*] 开始扫描漏洞")
	Plugins.CheckIP(targetIP)
	start := time.Now()
	Plugins.Check0638()
	Plugins.Check14882()
	Plugins.Check3510()
	Plugins.Check10271()
	Plugins.Check3248()
	Plugins.Check3506()
	Plugins.Check2894()
	Plugins.Check2893()
	Plugins.Check2628()
	Plugins.Check2725()
	Plugins.Check2729()
	Plugins.Check2890()
	t := time.Now().Sub(start)
	fmt.Printf("[*] 扫描结束,耗时: %s\n", t)
}
