package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/panjf2000/gnet"
	"github.com/panjf2000/gnet/pool/goroutine"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// map to reference for connections
var globeMap = make(map[gnet.Conn]*rsa.PrivateKey)

// codecServer used for initializing the server

type codecServer struct {
	*gnet.EventServer
	addr       string
	multicore  bool
	async      bool
	codec      gnet.ICodec
	workerPool *goroutine.Pool
}

func decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		panic(err)
	}
	return string(plaintext)
}


// Multithreading response handler
func multithread() bool {
	// Get multithreading
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Multithreading (true/false): ")
	text, _ := reader.ReadString('\n')
	text = strings.TrimSuffix(text, "\n")
	newbool, err := strconv.ParseBool(text)
	if err != nil {
		panic(err)
		return multithread()
	}
	return newbool
}

// Server event handlers
func (cs *codecServer) OnInitComplete(srv gnet.Server) (action gnet.Action) {
	log.Printf("RandomServer is listening on %s (multi-cores: %t, loops: %d)\n",
		srv.Addr.String(), srv.Multicore, srv.NumEventLoop)
	return
}

func (cs *codecServer) OnOpened(c gnet.Conn) (out []byte, action gnet.Action) {
	log.Println("A new connection has been made from: ", c.RemoteAddr().String())
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	globeMap[c] = privateKey
	byt, err := json.Marshal(privateKey.PublicKey)
	c.AsyncWrite(byt)
	return
}

func (cs *codecServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	if cs.async {
		data := append([]byte{}, frame...)
		datum := decrypt(string(data), *globeMap[c])
		_ = cs.workerPool.Submit(func() {
			fmt.Println(string(datum))
		})
		return
	}
	out = frame
	return
}

// Server initializer
func CodecServe(addr string, multicore, async bool, codec gnet.ICodec) {
	var err error

	// Creates protocol for encoding frames
	if codec == nil {
		encoderConfig := gnet.EncoderConfig{
			ByteOrder:                       binary.BigEndian,
			LengthFieldLength:               4,
			LengthAdjustment:                0,
			LengthIncludesLengthFieldLength: false,
		}
		decoderConfig := gnet.DecoderConfig{
			ByteOrder:           binary.BigEndian,
			LengthFieldOffset:   0,
			LengthFieldLength:   4,
			LengthAdjustment:    0,
			InitialBytesToStrip: 4,
		}
		codec = gnet.NewLengthFieldBasedFrameCodec(encoderConfig, decoderConfig)
	}

	// Initializes codecServer for gnet.Serve function
	cs := &codecServer{addr: addr, multicore: multicore, async: async, codec: codec, workerPool: goroutine.Default()}

	// Serves the port
	err = gnet.Serve(cs, addr, gnet.WithMulticore(multicore), gnet.WithTCPKeepAlive(time.Minute*5), gnet.WithCodec(codec))
	if err != nil {
		panic(err)
	}
}

func main() {
	// Start Server
	multi := multithread()
	addr := fmt.Sprintf("tcp://:%d", 9000)
	CodecServe(addr, multi, true, nil)
}
