package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/codegangsta/cli"
	"github.com/xtaci/kcp-go"
)

const (
	BUFSIZ = 65536
)

var (
	ch_buf chan []byte
	iv     []byte = []byte{147, 243, 201, 109, 83, 207, 190, 153, 204, 106, 86, 122, 71, 135, 200, 20}
)

func init() {
	ch_buf = make(chan []byte, 1024)
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
			Value: "kcp",
			Usage: "transportation mode",
		},
		cli.StringFlag{
			Name:  "localaddr,l",
			Value: ":12948",
			Usage: "local listen addr:",
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
		addr, err := net.ResolveTCPAddr("tcp", c.String("localaddr"))
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
			go handleClient(conn, c.String("remoteaddr"), c.String("key"), c.String("mode"))
		}
	}
	cliApp.Run(os.Args)
}

func peer(sess_die chan struct{}, remote string, key string, mode string) (net.Conn, <-chan []byte) {
	switch mode {
	case "kcp":
		return kcpPeer(sess_die, remote, key)
	case "tcp":
		return tcpPeer(sess_die, remote, key)
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
	conn, err := kcp.DialEncrypted(kcp.MODE_FAST, remote, key)
	if err != nil {
		log.Println(err)
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

func client(conn net.Conn, sess_die chan struct{}, key string) <-chan []byte {
	ch := make(chan []byte, 1024)
	go func() {
		defer func() {
			close(ch)
		}()

		// encoder
		commkey := make([]byte, 32)
		copy(commkey, []byte(key))
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
			encoder.XORKeyStream(bts, bts)
			select {
			case ch <- bts:
			case <-sess_die:
				return
			}
		}
	}()
	return ch
}

func handleClient(conn *net.TCPConn, remote string, key string, mode string) {
	log.Println("stream opened")
	defer log.Println("stream closed")
	sess_die := make(chan struct{})
	defer func() {
		close(sess_die)
		conn.Close()
	}()

	conn_peer, ch_peer := peer(sess_die, remote, key, mode)
	ch_client := client(conn, sess_die, key)
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
