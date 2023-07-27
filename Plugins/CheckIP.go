package Plugins

import (
	"fmt"
	"os"
	"os/exec"
)

func isFileEmpty(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return true, nil // 文件不存在，认为是空文件
	} else if err != nil {
		return false, err // 其他错误，返回错误信息
	}

	if info.Size() == 0 {
		return true, nil // 文件存在但为空
	}

	return false, nil // 文件存在且非空
}

func CheckIP(targetIP string) {
	CheckSH()
	filename := "targets.txt" // 文件名
	isEmpty, err := isFileEmpty(filename)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if isEmpty {
		// 执行 portScan.sh 脚本
		cmd := exec.Command("sh", "portScan.sh", targetIP)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error running portScan.sh:", err)
			return
		}
	}
}
