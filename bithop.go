package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	Magic           uint32 = 0xD9B4BEF9
	ProtocolVersion uint32 = 70015
)

var dnsSeeds = []string{
	"seed.bitcoin.sprovoost.nl",
	"dnsseed.emzy.de",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoin.wiz.biz",
	"seed.bitnodes.io",
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
}

var nodes = struct {
	sync.Mutex
	addrs map[string]bool
}{addrs: make(map[string]bool)}

var outputFile *os.File

func main() {
	var wg sync.WaitGroup

	// Open file for saving nodes
	var err error
	outputFile, err = os.Create("nodes.txt")
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer outputFile.Close()

	// Prompt user for the number of goroutines
	var numGoroutines int
	fmt.Print("Enter the number of goroutines: ")
	fmt.Scanln(&numGoroutines)

	// Resolve DNS seeds
	for _, seed := range dnsSeeds {
		wg.Add(1)
		go func(seed string) {
			defer wg.Done()
			resolveDNS(seed)
		}(seed)
	}
	wg.Wait()

	// Create a channel to manage tasks
	taskChan := make(chan string, len(nodes.addrs))

	// Add nodes to the task channel
	for addr := range nodes.addrs {
		taskChan <- addr
	}
	close(taskChan)

	// Create worker pool
	var workerWG sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for addr := range taskChan {
				connectToNode(addr)
			}
		}()
	}

	workerWG.Wait()
}

func resolveDNS(seed string) {
	addrs, err := net.LookupHost(seed)
	if err != nil {
		fmt.Printf("DNS lookup failed for %s: %v\n", seed, err)
		return
	}

	nodes.Lock()
	defer nodes.Unlock()
	for _, addr := range addrs {
		if strings.Contains(addr, ":") {
			nodes.addrs["["+addr+"]:8333"] = true
		} else {
			nodes.addrs[addr+":8333"] = true
		}
	}
}

func connectToNode(addr string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("Connection to %s failed: %v\n", addr, err)
		return
	}
	defer conn.Close()

	if err := handshake(conn); err != nil {
		fmt.Printf("Handshake with %s failed: %v\n", addr, err)
		return
	}

	if err := sendMessage(conn, "getaddr", nil); err != nil {
		fmt.Printf("Sending getaddr to %s failed: %v\n", addr, err)
		return
	}

	for {
		command, payload, err := receiveMessage(conn)
		if err != nil {
			fmt.Printf("Receiving addr from %s failed: %v\n", addr, err)
			return
		}

		if command == "addr" {
			processAddrPayload(payload)
		}
	}
}

func processAddrPayload(payload []byte) {
	count, bytesRead := decodeVarInt(payload)
	for i := 0; i < int(count); i++ {
		if bytesRead+30 > len(payload) {
			return
		}
		addrData := payload[bytesRead : bytesRead+30]
		bytesRead += 30

		timestamp := binary.LittleEndian.Uint32(addrData[0:4])
		if time.Now().Unix()-int64(timestamp) > 3*60*60 {
			continue
		}

		services := binary.LittleEndian.Uint64(addrData[4:12])
		if services&1 == 0 {
			continue
		}

		ipBytes := addrData[12:28]
		port := binary.BigEndian.Uint16(addrData[28:30])
		ip := net.IP(ipBytes)
		addr := fmt.Sprintf("[%s]:%d", ip, port)
		if ip.To4() != nil {
			addr = fmt.Sprintf("%s:%d", ip, port)
		}

		nodes.Lock()
		if !nodes.addrs[addr] {
			nodes.addrs[addr] = true
			nodes.Unlock()
			go connectToNode(addr) // Start a new goroutine for each new node
		} else {
			nodes.Unlock()
		}

		// Save to file
		saveNode(addr)
	}
}

func saveNode(addr string) {
	nodes.Lock()
	defer nodes.Unlock()
	_, err := outputFile.WriteString(addr + "\n")
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
	}
}

func handshake(conn net.Conn) error {
	if err := sendMessage(conn, "version", createVersionPayload()); err != nil {
		return err
	}

	for {
		command, _, err := receiveMessage(conn)
		if err != nil {
			return err
		}

		switch command {
		case "version":
			if err := sendMessage(conn, "verack", nil); err != nil {
				return err
			}
		case "verack":
			return nil
		}
	}
}

func sendMessage(conn net.Conn, command string, payload []byte) error {
	_, err := conn.Write(packCommand(command, payload))
	if err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "broken pipe") {
			return fmt.Errorf("connection closed: %v", err)
		}
		return err
	}
	return nil
}

func receiveMessage(conn net.Conn) (string, []byte, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(conn, header); err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "broken pipe") {
			return "", nil, fmt.Errorf("connection closed: %v", err)
		}
		return "", nil, err
	}

	length := binary.LittleEndian.Uint32(header[16:20])
	command := strings.TrimRight(string(header[4:16]), "\x00")
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "broken pipe") {
				return "", nil, fmt.Errorf("connection closed: %v", err)
			}
			return "", nil, err
		}
		firstSHA := sha256.Sum256(payload)
		checksum := sha256.Sum256(firstSHA[:])
		if !bytes.Equal(checksum[:4], header[20:24]) {
			return "", nil, fmt.Errorf("invalid checksum")
		}
	}

	return command, payload, nil
}

func packCommand(command string, payload []byte) []byte {
	var cmd [12]byte
	copy(cmd[:], command)

	firstSHA := sha256.Sum256(payload)
	checksum := sha256.Sum256(firstSHA[:])

	packet := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(packet[0:4], Magic)
	copy(packet[4:16], cmd[:])
	binary.LittleEndian.PutUint32(packet[16:20], uint32(len(payload)))
	copy(packet[20:24], checksum[:4])
	copy(packet[24:], payload)

	return packet
}

func createVersionPayload() []byte {
	var addr [26]byte
	binary.LittleEndian.PutUint64(addr[:8], 1)

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.LittleEndian, ProtocolVersion)
	binary.Write(payload, binary.LittleEndian, uint64(1)) // Services
	binary.Write(payload, binary.LittleEndian, uint64(time.Now().Unix()))
	payload.Write(addr[:]) // Receiver address
	payload.Write(addr[:]) // Sender address
	binary.Write(payload, binary.LittleEndian, rand.Uint64()) // Nonce
	payload.Write([]byte{0}) // User agent (empty string)
	binary.Write(payload, binary.LittleEndian, int32(0)) // Start height
	payload.WriteByte(0) // Relay

	return payload.Bytes()
}

func decodeVarInt(payload []byte) (uint64, int) {
	if len(payload) < 1 {
		return 0, 0
	}
	firstByte := payload[0]

	if firstByte < 0xfd {
		return uint64(firstByte), 1
	} else if firstByte == 0xfd {
		return uint64(binary.LittleEndian.Uint16(payload[1:3])), 3
	} else if firstByte == 0xfe {
		return uint64(binary.LittleEndian.Uint32(payload[1:5])), 5
	} else {
		return binary.LittleEndian.Uint64(payload[1:9]), 9
	}
}
