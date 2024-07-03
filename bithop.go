package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"fmt"
	"io"
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	Magic           uint32 = 0xD9B4BEF9
	ProtocolVersion uint32 = 77777
	PauseInterval   int    = 1000
)

var dnsSeeds = []string{
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"seed.bitcoin.jonasschnelli.ch",
	"seed.btc.petertodd.org",
	"seed.bitcoin.sprovoost.nl",
	"dnsseed.emzy.de",
	"seed.bitcoin.wiz.biz",
	"seed.bitnodes.io",
	"seed.bitcoin.bloqseeds.net",
	"seed.ob1.io",
	"seed.blockchain.info",
	"seed.bitcoincore.org",
	"seed.bitcoin.netpro.app",
	"seed.bitcoin.jbrux.com",
	"seed.bitcoinlabs.org",
	"seed.bitcoin.trezor.io",
	"seed.bitcoin.slushpool.com",
	"seed.multidoge.org",
	"seed.voskuil.org",
	"seed.bitprim.org",
	"seed.flowee.dev",
	"seed.bitpay.com",
	"seed.bccapi.org",
	"seed.bchd.cash",
	"seed.flowee.cash",
	"seed.bitcoin.no",
	"seed.bitcoiner.me",
	"seed.jochen-hoenicke.de",
	"seed.bhd.cash",
	"seed.bchd.cash",
	"seed.deadalnix.me",
	"dnsseed.cypherpunks.ru",
}

var nodes = struct {
	sync.Mutex
	addrs map[string]bool
}{addrs: make(map[string]bool)}

var (
	outputFile    *os.File
	totalCollected int
	totalMutex    sync.Mutex
	startTime     time.Time
)

func main() {
	displayArt()
	fmt.Print("\n")

	startTime = time.Now()
	var wg sync.WaitGroup

	var err error
	outputFile, err = os.Create("nodes.txt")
	if err != nil {
		fmt.Printf("error creating file: %v\n", err)
		return
	}
	defer outputFile.Close()

	var numGoroutines int
	fmt.Print("enter amount of parallel threads: ")
	fmt.Scanln(&numGoroutines)
	fmt.Print("\n")

	for _, seed := range dnsSeeds {
		wg.Add(1)
		go func(seed string) {
			defer wg.Done()
			resolveDNS(seed)
		}(seed)
	}
	wg.Wait()

	taskChan := make(chan string, len(nodes.addrs))

	for addr := range nodes.addrs {
		taskChan <- addr
	}
	close(taskChan)

	var workerWG sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		workerWG.Add(1)
		go func(threadID int) {
			defer workerWG.Done()
			for addr := range taskChan {
				connectToNode(addr, threadID)
			}
		}(i + 1)
	}

	go monitorProgress()

	workerWG.Wait()
	fmt.Println()
}

func monitorProgress() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	fmt.Printf("\033[s")
	for range ticker.C {
		totalMutex.Lock()
		ipsPerMinute := float64(totalCollected) / time.Since(startTime).Minutes()
		fmt.Printf("\033[u\033[2K\rtotal ip addresses collected: %d, ips per minute: %.2f", totalCollected, ipsPerMinute)
		totalMutex.Unlock()
	}
	fmt.Println()
}

func displayArt() {
    esc := "\x1b"

    ansiArt := `
%[1]s[49m                         %[1]s[m
%[1]s[49m                         %[1]s[m
%[1]s[49m     %[1]s[38;5;64;49m▄%[1]s[38;5;100;48;5;106m▄%[1]s[38;5;100;48;5;70m▄%[1]s[38;5;178;48;5;106m▄%[1]s[38;5;107;48;5;106m▄%[1]s[38;5;70;48;5;64m▄%[1]s[38;5;184;48;5;70m▄%[1]s[38;5;106;48;5;106m▄%[1]s[38;5;106;48;5;150m▄%[1]s[38;5;70;48;5;70m▄%[1]s[38;5;64;48;5;106m▄%[1]s[38;5;3;48;5;70m▄%[1]s[38;5;3;48;5;64m▄%[1]s[38;5;142;48;5;149m▄%[1]s[38;5;149;49m▄%[1]s[49m     %[1]s[m
%[1]s[49m     %[1]s[38;5;100;48;5;100m▄%[1]s[38;5;232;48;5;222m▄%[1]s[38;5;233;48;5;232m▄%[1]s[38;5;234;48;5;243m▄%[1]s[38;5;3;48;5;100m▄%[1]s[38;5;106;48;5;113m▄%[1]s[38;5;148;48;5;112m▄%[1]s[38;5;149;48;5;149m▄%[1]s[38;5;149;48;5;148m▄%[1]s[38;5;70;48;5;70m▄%[1]s[38;5;52;48;5;95m▄%[1]s[38;5;233;48;5;252m▄%[1]s[38;5;0;48;5;232m▄%[1]s[38;5;236;48;5;252m▄%[1]s[38;5;178;48;5;143m▄%[1]s[49m     %[1]s[m
%[1]s[49m     %[1]s[38;5;64;48;5;136m▄%[1]s[38;5;3;48;5;101m▄%[1]s[38;5;94;48;5;236m▄%[1]s[38;5;178;48;5;236m▄%[1]s[38;5;106;48;5;100m▄%[1]s[38;5;112;48;5;70m▄%[1]s[38;5;106;48;5;149m▄%[1]s[38;5;191;48;5;191m▄%[1]s[38;5;149;48;5;191m▄%[1]s[38;5;191;48;5;112m▄%[1]s[38;5;142;48;5;3m▄%[1]s[38;5;100;48;5;236m▄%[1]s[38;5;136;48;5;235m▄%[1]s[38;5;142;48;5;143m▄%[1]s[38;5;186;48;5;106m▄%[1]s[49m     %[1]s[m bithop beta v2
%[1]s[49m     %[1]s[38;5;106;48;5;148m▄%[1]s[38;5;70;48;5;148m▄%[1]s[38;5;64;48;5;106m▄%[1]s[38;5;106;48;5;106m▄%[1]s[38;5;64;48;5;112m▄%[1]s[38;5;106;48;5;148m▄%[1]s[38;5;3;48;5;149m▄%[1]s[38;5;125;48;5;191m▄%[1]s[38;5;101;48;5;191m▄%[1]s[38;5;3;48;5;191m▄%[1]s[38;5;106;48;5;191m▄%[1]s[38;5;149;48;5;148m▄%[1]s[38;5;149;48;5;106m▄%[1]s[38;5;148;48;5;142m▄%[1]s[38;5;191;48;5;149m▄%[1]s[49m     %[1]s[m kevin mcsheehan (pad)
%[1]s[49m      %[1]s[49;38;5;58m▀%[1]s[49;38;5;70m▀%[1]s[38;5;64;48;5;70m▄%[1]s[38;5;64;48;5;112m▄%[1]s[38;5;64;48;5;149m▄▄%[1]s[38;5;70;48;5;148m▄%[1]s[38;5;64;48;5;191m▄▄▄%[1]s[38;5;64;48;5;149m▄%[1]s[49;38;5;148m▀%[1]s[49;38;5;64m▀%[1]s[49m      %[1]s[m x.com/123456
%[1]s[49m     %[1]s[38;5;106;49m▄%[1]s[38;5;149;49m▄%[1]s[38;5;106;49m▄%[1]s[38;5;106;48;5;148m▄%[1]s[38;5;3;48;5;70m▄%[1]s[38;5;227;48;5;142m▄%[1]s[38;5;229;48;5;149m▄▄▄%[1]s[38;5;227;48;5;148m▄%[1]s[38;5;185;48;5;64m▄%[1]s[38;5;70;48;5;70m▄%[1]s[38;5;106;48;5;107m▄%[1]s[38;5;70;49m▄%[1]s[38;5;150;49m▄%[1]s[38;5;15;49m▄%[1]s[49m    %[1]s[m
%[1]s[49m     %[1]s[38;5;64;48;5;106m▄%[1]s[38;5;58;48;5;64m▄%[1]s[38;5;70;48;5;70m▄%[1]s[38;5;112;48;5;106m▄%[1]s[38;5;58;48;5;64m▄%[1]s[38;5;64;48;5;100m▄%[1]s[38;5;185;48;5;228m▄%[1]s[38;5;221;48;5;230m▄%[1]s[38;5;185;48;5;228m▄%[1]s[38;5;184;48;5;227m▄%[1]s[38;5;3;48;5;58m▄%[1]s[38;5;185;48;5;58m▄%[1]s[38;5;112;48;5;112m▄%[1]s[38;5;64;48;5;70m▄%[1]s[38;5;70;48;5;106m▄%[1]s[38;5;106;48;5;148m▄%[1]s[49m    %[1]s[m
%[1]s[49m    %[1]s[38;5;106;49m▄%[1]s[38;5;64;48;5;58m▄▄%[1]s[38;5;22;48;5;234m▄%[1]s[38;5;106;48;5;106m▄%[1]s[38;5;106;48;5;64m▄%[1]s[38;5;234;48;5;58m▄%[1]s[38;5;142;48;5;142m▄%[1]s[38;5;136;48;5;178m▄%[1]s[38;5;136;48;5;142m▄%[1]s[38;5;3;48;5;136m▄%[1]s[38;5;106;48;5;58m▄%[1]s[38;5;106;48;5;106m▄%[1]s[38;5;22;48;5;65m▄%[1]s[38;5;64;48;5;22m▄%[1]s[38;5;70;48;5;64m▄%[1]s[38;5;107;49m▄%[1]s[49m    %[1]s[m
%[1]s[49m    %[1]s[49;38;5;106m▀▀%[1]s[49;38;5;149m▀%[1]s[49;38;5;106m▀%[1]s[38;5;149;48;5;64m▄%[1]s[38;5;64;48;5;106m▄%[1]s[38;5;149;48;5;106m▄%[1]s[38;5;58;48;5;107m▄%[1]s[49m %[1]s[38;5;58;48;5;106m▄%[1]s[38;5;107;48;5;106m▄%[1]s[38;5;64;48;5;112m▄%[1]s[38;5;107;48;5;143m▄%[1]s[49;38;5;64m▀%[1]s[49;38;5;70m▀%[1]s[38;5;237;48;5;106m▄%[1]s[49;38;5;113m▀%[1]s[49;38;5;148m▀%[1]s[49m   %[1]s[m
%[1]s[49m                         %[1]s[m
%[1]s[49m                         %[1]s[m
`

    fmt.Printf(ansiArt, esc)
}

func resolveDNS(seed string) {
	addrs, err := net.LookupHost(seed)
	if err != nil {
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

func connectToNode(addr string, threadID int) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	if err := handshake(conn); err != nil {
		return
	}

	if err := sendMessage(conn, "getaddr", nil); err != nil {
		return
	}

	for {
		command, payload, err := receiveMessage(conn)
		if err != nil {
			return
		}

		if command == "addr" {
			processAddrPayload(payload, threadID)
		}
	}
}

func processAddrPayload(payload []byte, threadID int) {
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
			go connectToNode(addr, threadID)
		} else {
			nodes.Unlock()
		}

		saveNode(addr)
		totalMutex.Lock()
		totalCollected++
		if totalCollected%PauseInterval == 0 {
			removeDuplicates()
		}
		totalMutex.Unlock()
	}
}

func removeDuplicates() {
	fmt.Println(" - removing duplicates...")
	nodes.Lock()
	defer nodes.Unlock()

	uniqueAddrs := make(map[string]bool)
	outputFile.Seek(0, 0)
	scanner := bufio.NewScanner(outputFile)
	for scanner.Scan() {
		addr := scanner.Text()
		uniqueAddrs[addr] = true
	}

	outputFile.Truncate(0)
	outputFile.Seek(0, 0)
	for addr := range uniqueAddrs {
		outputFile.WriteString(addr + "\n")
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
		return err
	}
	return nil
}

func receiveMessage(conn net.Conn) (string, []byte, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", nil, err
	}

	length := binary.LittleEndian.Uint32(header[16:20])
	command := strings.TrimRight(string(header[4:16]), "\x00")
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
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
	binary.Write(payload, binary.LittleEndian, uint64(1))
	binary.Write(payload, binary.LittleEndian, uint64(time.Now().Unix()))
	payload.Write(addr[:])
	payload.Write(addr[:])
	binary.Write(payload, binary.LittleEndian, rand.Uint64())
	payload.Write([]byte{0})
	binary.Write(payload, binary.LittleEndian, int32(0))
	payload.WriteByte(0)

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
