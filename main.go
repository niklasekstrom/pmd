package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const (
	IP_HDRINCL = 0x3
	SO_RCVTIMEO = 0x14
	UDP_PORT = 9332
	MAX_TRIES = 3
	TRY_TIMEOUT = 1.0
	MTU_MINSIZE = 68
	MTU_MAXSIZE = 65535

	CMD_PING = 1
	CMD_PONG = 2
	CMD_START_RPMD = 3
	CMD_RPMD_RESULT = 4
)

type packet struct {
	Vhl		uint8
	Tos   	uint8
	IpLen 	uint16
	Id    	uint16
	Off   	uint16
	Ttl   	uint8
	Proto 	uint8
	IpCsum  uint16
	SrcAddr [4]byte
	DstAddr [4]byte

	SrcPort uint16
	DstPort uint16
	UdpLen 	uint16
	UdpCsum uint16

	Command	uint32
	Arg		int32
}

var sendBuf [65536]byte
var recvBuf [65536]byte

var sendPkt = packet{
	Vhl: 0x45,
	Ttl: 64,
	Off: 0x4000,
	Proto: syscall.IPPROTO_UDP,
}

var recvPkt packet
var fd syscall.Handle

var passive = false
var localAddr [4]byte
var remoteAddr [4]byte

var rpmdSent time.Time
var rpmdComplete = false
var rpmdResult = -1
var rpmdAttempts = 0

type pmdState struct {
	addr [4]byte
	port int

	mtuBest int
	mtuLowerBound int
	mtuUpperBound int
	mtuCurrent int

	triesLeft int
	tryStarted time.Time

	complete bool
	ended time.Time
}

var pmds map[[4]byte]*pmdState

func sendPacket(n int) error {
	//fmt.Printf("Sending packet to %v:%v\n", sendPkt.DstAddr, sendPkt.DstPort)

	sendPkt.IpLen = uint16(n)
	sendPkt.UdpLen = uint16(n - 20)

	b := bytes.NewBuffer(sendBuf[:0])
	binary.Write(b, binary.BigEndian, &sendPkt)

	toAddr := syscall.SockaddrInet4{Port: int(sendPkt.DstPort), Addr: sendPkt.DstAddr}

	err := syscall.Sendto(fd, sendBuf[:n], 0, &toAddr)
	if err != nil && err != syscall.EMSGSIZE {
		fmt.Fprintf(os.Stderr, "Sendto failed: %v\n", err)
		os.Exit(1)
	}

	return err
}

func startAttempt(s *pmdState) {
	for s.mtuLowerBound <= s.mtuUpperBound {
		s.mtuCurrent = (s.mtuLowerBound + s.mtuUpperBound) / 2

		if s.triesLeft == MAX_TRIES {
			fmt.Printf("Testing MTU size %v bytes...", s.mtuCurrent)
		}

		s.tryStarted = time.Now()

		sendPkt.DstAddr = s.addr
		sendPkt.DstPort = uint16(s.port)
		sendPkt.Command = CMD_PING

		err := sendPacket(s.mtuCurrent)
		if err == syscall.EMSGSIZE {
			fmt.Printf("packet too big for local interface\n")
			s.mtuUpperBound = s.mtuCurrent - 1
			s.triesLeft = MAX_TRIES
			continue
		}

		return
	}

	s.complete = true
	s.ended = time.Now()

	if s.mtuBest == -1 {
		fmt.Fprintf(os.Stderr, "No reply from %v.\n", s.addr)
	} else {
		fmt.Printf("\nPath MTU to %v is found to be: %v bytes (20 IPv4 header + 8 UDP header + %v data).\n",
			s.addr, s.mtuBest, s.mtuBest - 20 - 8)
	}

	if passive {
		sendPkt.DstAddr = s.addr
		sendPkt.DstPort = uint16(s.port)
		sendPkt.Command = CMD_RPMD_RESULT
		sendPkt.Arg = int32(s.mtuBest)
		sendPacket(36)
	}

	if !passive && rpmdComplete {
		fmt.Printf("\nReverse path MTU from %v is: %v bytes\n", remoteAddr, rpmdResult)
		os.Exit(0)
	}
}

func sendRpmdReq() {
	sendPkt.DstAddr = remoteAddr
	sendPkt.DstPort = UDP_PORT
	sendPkt.Command = CMD_START_RPMD
	sendPacket(36)
	rpmdSent = time.Now()
	rpmdAttempts += 1
	fmt.Printf("Sending request to perform reverse PMD from %v\n", remoteAddr)
}

func timeout() {
	if !passive && !rpmdComplete && time.Now().Sub(rpmdSent).Seconds() >= 2.0 {
		sendRpmdReq()
	}

	for _, s := range pmds {
		if !s.complete && time.Now().Sub(s.tryStarted).Seconds() >= TRY_TIMEOUT {
			s.triesLeft -= 1
			if s.triesLeft == 0 {
				fmt.Printf("no response, invalid MTU size\n")

				s.triesLeft = MAX_TRIES
				s.mtuUpperBound = s.mtuCurrent - 1
			}
			startAttempt(s)
		}
	}
}

func startPmd(addr [4]byte, port int) {
	s := new(pmdState)
	s.addr = addr
	s.port = port
	s.mtuBest = -1
	s.mtuLowerBound = MTU_MINSIZE
	s.mtuUpperBound = MTU_MAXSIZE
	s.triesLeft = MAX_TRIES
	s.complete = false

	pmds[addr] = s

	startAttempt(s)
}

func handleReceivedPacket() {
	switch recvPkt.Command {
	case CMD_PING:
		sendPkt.DstAddr = recvPkt.SrcAddr
		sendPkt.DstPort = recvPkt.SrcPort
		sendPkt.Command = CMD_PONG
		sendPkt.Arg = int32(recvPkt.IpLen)
		sendPacket(36)

	case CMD_PONG:
		s := pmds[recvPkt.SrcAddr]

		if s != nil && int(recvPkt.Arg) == s.mtuCurrent {
			fmt.Printf("valid\n")
	
			s.triesLeft = MAX_TRIES
			s.mtuLowerBound = s.mtuCurrent + 1
		
			if s.mtuCurrent > s.mtuBest {
				s.mtuBest = s.mtuCurrent
			}
	
			startAttempt(s)
		}

	case CMD_START_RPMD:
		s := pmds[recvPkt.SrcAddr]

		if s != nil && s.complete && time.Now().Sub(s.ended).Seconds() < 5.0 {
			sendPkt.DstAddr = recvPkt.SrcAddr
			sendPkt.DstPort = recvPkt.SrcPort
			sendPkt.Command = CMD_RPMD_RESULT
			sendPkt.Arg = int32(s.mtuBest)
			sendPacket(36)
		} else if s == nil || s.complete {
			startPmd(recvPkt.SrcAddr, int(recvPkt.SrcPort))
		}

	case CMD_RPMD_RESULT:
		if !passive && !rpmdComplete && recvPkt.SrcAddr == remoteAddr {
			rpmdResult = int(recvPkt.Arg)
			rpmdComplete = true

			if pmds[remoteAddr].complete {
				fmt.Printf("\nReverse path MTU from %v is: %v bytes\n", remoteAddr, rpmdResult)
				os.Exit(0)
			}
		}
	}
}

func main() {
	pmds = make(map[[4]byte]*pmdState)

	localAddrStr := ""
	remoteAddrStr := ""

	flag.StringVar(&localAddrStr, "local", "", "IP address of local process")
	flag.StringVar(&remoteAddrStr, "remote", "", "IP address of remote process")
	flag.Parse()

	if localAddrStr == "" {
		fmt.Fprintf(os.Stderr, "Must supply a local address\n")
		os.Exit(1)
	} else {
		addrIP := net.ParseIP(localAddrStr)
		if addrIP == nil {
			fmt.Fprintf(os.Stderr, "Invalid local address: %v\n", localAddrStr)
			os.Exit(1)
		}
		fourAddr := addrIP.To4()
		if fourAddr == nil {
			fmt.Fprintf(os.Stderr, "Not an IPv4 address: %v\n", addrIP)
			os.Exit(1)
		}
		copy(localAddr[:], fourAddr)
	}

	if remoteAddrStr == "" {
		passive = true
	} else {
		addrIP := net.ParseIP(remoteAddrStr)
		if addrIP == nil {
			fmt.Fprintf(os.Stderr, "Invalid remote IP: %v\n", remoteAddrStr)
			os.Exit(1)
		}
		fourAddr := addrIP.To4()
		if fourAddr == nil {
			fmt.Fprintf(os.Stderr, "Not an IPv4 address: %v\n", addrIP)
			os.Exit(1)
		}
		copy(remoteAddr[:], fourAddr)
	}

	var err error
	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
	if err != nil || fd < 0 {
		fmt.Fprintf(os.Stderr, "Error opening raw socket: %v\n", err)
		os.Exit(1)
	}

	localSa := syscall.SockaddrInet4{Port: UDP_PORT, Addr: localAddr}
	err = syscall.Bind(fd, &localSa)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error binding socket to local address: %v\n", err)
		os.Exit(1)
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_HDRINCL, 1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error enabling IP_HDRINCL: %v\n", err)
		os.Exit(1)
	}

	tv := syscall.Timeval{Sec: 0, Usec: 500 * 1000}
	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, SO_RCVTIMEO, &tv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting receive timeout: %v\n", err)
		os.Exit(1)
	}

	for i := 0; i < 65536; i++ {
		sendBuf[i] = byte('a') + byte(i % 26)
	}

	sendPkt.SrcAddr = localAddr
	sendPkt.SrcPort = uint16(UDP_PORT)

	sendPkt.DstAddr = remoteAddr
	sendPkt.DstPort = uint16(UDP_PORT)

	if passive {
		fmt.Printf("Running in passive mode\n")
	} else {
		sendRpmdReq()
		startPmd(remoteAddr, UDP_PORT)
	}

	for {
		n, _, err := syscall.Recvfrom(fd, recvBuf[:], 0)
		if err != nil {
			if err == syscall.EAGAIN {
				timeout()
				continue
			}
			fmt.Fprintf(os.Stderr, "Recvfrom failed: %v\n", err)
			os.Exit(1)
		}

		if n >= 36 {
			b := bytes.NewReader(recvBuf[:36])
			binary.Read(b, binary.BigEndian, &recvPkt)
			if recvPkt.DstPort == UDP_PORT {
				handleReceivedPacket()
			}
		}

		timeout()
	}
}
