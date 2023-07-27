#!/bin/bash
DIR="targets.txt"
check_weblogic_port() {
  IP=$1
  PORT=$2
  response=$(curl -Is "http://$IP:$port/console" | head -n 1)
  if [[ $response == *"302"* ]]; then
    echo "$IP:$PORT" >$DIR
  fi
}

if [ -z $1 ]; then
  echo -e "\e[32m使用方法：./portScan.sh IP\n如有需要请自行修改端口探测范围\e[0m"

  exit
fi

for port in {8000..9000}; do
  if [ -f $DIR ]; then
    break
  fi
  check_weblogic_port $1 $port &
done
wait
