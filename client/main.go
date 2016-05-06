package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/xtaci/kcp-go"

	"github.com/codegangsta/cli"
)

const (
	BUFSIZ = 65536
)

var (
	ch_buf chan []byte
	ch_tun chan gopacket.Packet
	iv     []byte = []byte{147, 243, 201, 109, 83, 207, 190, 153, 204, 106, 86, 122, 71, 135, 200, 20}
)

func init() {
	ch_buf = make(chan []byte, 1024)
	ch_tun = make(chan gopacket.Packet, 1024)
	go func() {
		for {
			ch_buf <- make([]byte, BUFSIZ)
		}
	}()

	rand.Seed(time.Now().UnixNano())
}

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = "finaltun"
	cliApp.Usage = "finaltun client"
	cliApp.Version = "1.0"
	cliApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "mode,m",
			Value: "tcp",
			Usage: "transportation mode can be tcp/kcp/fs",
		},
		cli.StringFlag{
			Name:  "device,d",
			Value: "lo0",
			Usage: "device ethernet:",
		},
		cli.StringFlag{
			Name:  "port,p",
			Value: "12948",
			Usage: "local listen port:",
		},
		cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "127.0.0.1:29900",
			Usage: "finaltun server addr",
		},
		cli.StringFlag{
			Name:  "key",
			Value: "it's a secrect",
			Usage: "key for communcation, must be the same as finaltun server",
		},
	}
	cliApp.Action = func(c *cli.Context) {
		addr, err := net.ResolveTCPAddr("tcp", ":"+c.String("port"))
		checkError(err)
		listener, err := net.ListenTCP("tcp", addr)
		checkError(err)
		log.Println("listening on:", listener.Addr())
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				log.Println("accept failed:", err)
				continue
			}
			go handleClient(conn, c)
		}
	}
	cliApp.Run(os.Args)
}

func peer(sess_die chan struct{}, c *cli.Context) (net.Conn, <-chan []byte) {
	switch c.String("mode") {
	case "tcp":
		return tcpPeer(sess_die, c.String("remoteaddr"), c.String("key"))
	case "kcp":
		return kcpPeer(sess_die, c.String("remoteaddr"), c.String("key"))
	case "fs":
		return fsPeer(sess_die, c.String("remoteaddr"), c.String("key"), c.String("device"), c.String("port"))
	default:
		panic("mode not support")
	}
}

func tcpPeer(sess_die chan struct{}, remote string, key string) (net.Conn, <-chan []byte) {
	conn, err := net.Dial("tcp", remote)
	if err != nil {
		log.Println(err)
		return nil, nil
	}
	ch := make(chan []byte, 1024)

	go func() {
		defer func() {
			close(ch)
		}()

		//decoder
		commkey := make([]byte, 32)
		copy(commkey, []byte(key))
		block, err := aes.NewCipher(commkey)
		if err != nil {
			log.Println(err)
			return
		}
		decoder := cipher.NewCTR(block, iv)

		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			bts := <-ch_buf
			if n, err := conn.Read(bts); err == nil {
				bts = bts[:n]
				decoder.XORKeyStream(bts, bts)
			} else if err, ok := err.(*net.OpError); ok && err.Timeout() {
				continue
			} else {
				log.Println(err)
				return
			}

			select {
			case ch <- bts:
			case <-sess_die:
				return
			}
		}
	}()
	return conn, ch
}

func kcpPeer(sess_die chan struct{}, remote string, key string) (net.Conn, <-chan []byte) {
	conn, err := kcp.DialEncrypted(kcp.MODE_FAST, remote, []byte(key))
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}
	ch := make(chan []byte, 1024)

	conn.SetWindowSize(128, 1024)
	go func() {
		defer func() {
			close(ch)
		}()

		//decoder
		commkey := make([]byte, 32)
		copy(commkey, []byte(key))
		block, err := aes.NewCipher(commkey)
		if err != nil {
			log.Println(err)
			return
		}
		decoder := cipher.NewCTR(block, iv)

		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			bts := <-ch_buf
			if n, err := conn.Read(bts); err == nil {
				bts = bts[:n]
				decoder.XORKeyStream(bts, bts)
			} else if err, ok := err.(*net.OpError); ok && err.Timeout() {
				continue
			} else {
				log.Println(err)
				return
			}

			select {
			case ch <- bts:
			case <-sess_die:
				return
			}
		}
	}()
	return conn, ch
}

func fsPeer(sess_die chan struct{}, remote string, key string, device string, port string) (net.Conn, <-chan []byte) {
	// TODO: conn := FSConn{}
	conn, err := net.Dial("tcp", remote)
	if err != nil {
		log.Fatal(err)
		return nil, nil
	}
	ch := make(chan []byte, 1024)
	go func() {
		defer func() {
			close(ch)
		}()
		//decoder
		commkey := make([]byte, 32)
		copy(commkey, []byte(key))
		block, err := aes.NewCipher(commkey)
		if err != nil {
			log.Println(err)
			return
		}
		decoder := cipher.NewCTR(block, iv)

		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			bts := <-ch_buf
			if n, err := conn.Read(bts); err == nil {
				bts = bts[:n]
				decoder.XORKeyStream(bts, bts)
			} else if err, ok := err.(*net.OpError); ok && err.Timeout() {
				continue
			} else {
				log.Println(err)
				return
			}

			packet := gopacket.NewPacket(bts, layers.LayerTypeTCP, gopacket.Default)
			resend := handlePacket(packet)

			select {
			case ch <- bts:
				if resend {
					// TODO: btc.serialNumber++
					// ch <- bts
				}
			case <-sess_die:
				return
			}
		}
	}()
	return conn, ch
}

type FSConn struct{}

func (FSConn) Read(b []byte) (n int, err error) {
	return 0, nil
}
func (FSConn) Write(b []byte) (n int, err error) {
	return 0, nil
}
func (FSConn) Close() error {
	return nil
}
func (FSConn) LocalAddr() net.Addr {
	return nil
}
func (FSConn) RemoteAddr() net.Addr {
	return nil
}
func (FSConn) SetDeadline(t time.Time) error {
	return nil
}
func (FSConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (FSConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func client(conn net.Conn, sess_die chan struct{}, c *cli.Context) <-chan []byte {
	ch := make(chan []byte, 1024)
	go func() {
		defer func() {
			close(ch)
		}()

		// encoder
		commkey := make([]byte, 32)
		copy(commkey, []byte(c.String("key")))
		block, err := aes.NewCipher(commkey)
		if err != nil {
			log.Println(err)
			return
		}
		encoder := cipher.NewCTR(block, iv)

		for {
			bts := <-ch_buf
			n, err := conn.Read(bts)
			if err != nil {
				log.Println(err)
				return
			}
			bts = bts[:n]

			packet := gopacket.NewPacket(bts, layers.LayerTypeTCP, gopacket.Default)
			resend := handlePacket(packet) && (c.String("mode") == "fs")

			encoder.XORKeyStream(bts, bts)
			select {
			case ch <- bts:
				if resend {
					// TODO: btc.serialNumber++
					// ch <- bts
				}
			case <-sess_die:
				return
			}
		}
	}()
	return ch
}

func handleClient(conn *net.TCPConn, c *cli.Context) {
	log.Println("stream opened")
	defer log.Println("stream closed")
	sess_die := make(chan struct{})
	defer func() {
		close(sess_die)
		conn.Close()
	}()

	conn_peer, ch_peer := peer(sess_die, c)
	ch_client := client(conn, sess_die, c)
	if conn_peer == nil {
		return
	}
	defer conn_peer.Close()

	for {
		select {
		case bts, ok := <-ch_peer:
			if !ok {
				return
			}
			if _, err := conn.Write(bts); err != nil {
				log.Println(err)
				return
			}
		case bts, ok := <-ch_client:
			if !ok {
				return
			}
			if _, err := conn_peer.Write(bts); err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func checkError(err error) {
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
}

func handlePacket(packet gopacket.Packet) bool {
	mac, ok := packet.LinkLayer().(*layers.Ethernet)
	if ok {
		log.Println("Ethernet", mac.LinkFlow())
	}
	ip, ok := packet.NetworkLayer().(*layers.IPv4)
	if ok {
		log.Println("IPv4", ip.NetworkFlow())
	}
	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if ok {
		if tcp.SYN && !tcp.ACK {
			log.Println("Sent NO1 handshake: ")
			return true
		}
		if tcp.SYN && tcp.ACK {
			log.Println("Receive NO2 handshake: ")
		}
		if !tcp.SYN && tcp.ACK && len(tcp.LayerPayload()) != 0 {
			return true
			log.Println("Sent NO3 handshake: ")
			log.Println("data", len(tcp.LayerPayload()))
		}
		log.Println("TCP", tcp.TransportFlow())
	}
	return false
}
