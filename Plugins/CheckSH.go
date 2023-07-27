package Plugins

import (
	"fmt"
	"io/ioutil"
	"os"
)

func CheckSH() {
	filename := "portScan.sh"
	content := "#!/bin/bash\nDIR=\"targets.txt\"\ncheck_weblogic_port() {\n  IP=$1\n  PORT=$2\n  response=$(curl -Is \"http://$IP:$port/console\" | head -n 1)\n  if [[ $response == *\"302\"* ]]; then\n    echo \"$IP:$PORT\" >$DIR\n  fi\n}\n\nif [ -z $1 ]; then\n  echo -e \"\\e[32m使用方法：./portScan.sh IP\\n如有需要请自行修改端口探测范围\\e[0m\"\n\n  exit\nfi\n\nfor port in {8000..9000}; do\n  if [ -f $DIR ]; then\n    break\n  fi\n  check_weblogic_port $1 $port &\ndone\nwait\n"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if err := ioutil.WriteFile(filename, []byte(content), 0755); err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
	}
}
