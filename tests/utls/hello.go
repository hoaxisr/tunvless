// Снимает ClientHello, который собрал бы uTLS для отпечатка Chrome, — эталон для сверки облика нашего
// Hello (tests/hellostruct.py). Запуск (Go 1.24+; модули — из go.mod Xray-core, uTLS v1.8.x):
//
//	go run hello.go auto|133|131|120 out.bin
//
// «auto» у uTLS сегодня — Chrome 133: гибрид X25519MLKEM768, ALPS с новым кодом 0x44cd, ECH GREASE. Это тот же
// отпечаток, который использует Xray-core при fp=chrome (transport/internet/tls).
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	var id utls.ClientHelloID
	switch os.Args[1] {
	case "auto":
		id = utls.HelloChrome_Auto
	case "133":
		id = utls.HelloChrome_133
	case "131":
		id = utls.HelloChrome_131
	case "120":
		id = utls.HelloChrome_120
	default:
		panic(os.Args[1])
	}
	fmt.Println("uTLS:", id.Client, id.Version)
	c1, c2 := net.Pipe()
	go func() {
		buf := make([]byte, 65536)
		n, _ := c2.Read(buf)
		os.WriteFile(os.Args[2], buf[:n], 0644)
		c2.Close()
	}()
	u := utls.UClient(c1, &utls.Config{ServerName: "www.example.com", InsecureSkipVerify: true}, id)
	u.SetDeadline(time.Now().Add(2 * time.Second))
	_ = u.BuildHandshakeState()
	_ = u.Handshake()
}
