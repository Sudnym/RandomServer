package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/panjf2000/gnet/pool/goroutine"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/monnand/dhkx"
	"github.com/panjf2000/gnet"
)

// connection used for storing cryptographic keys

type connection struct {
	myKey  *dhkx.DHKey
	oKey   *dhkx.DHKey
	finKey *dhkx.DHKey
	interf gnet.Conn
}

//codecServer used for initializing the server

type codecServer struct {
	*gnet.EventServer
	addr       string
	multicore  bool
	async      bool
	codec      gnet.ICodec
	workerPool *goroutine.Pool
}

// DHEX AES encrypt / decrypt functions
func encrypt(data []byte, key *dhkx.DHKey) []byte {
	block, _ := aes.NewCipher(key.Bytes())
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, key *dhkx.DHKey) []byte {
	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

// Multithreading response handler
func multithread() bool {
	// Get multithreading
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Multithreading (true/false): ")
	text, _ := reader.ReadString('\n')
	newbool, err := strconv.ParseBool(text)
	if err != nil {
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

func (cs *codecServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	if cs.async {
		data := append([]byte{}, frame...)
		_ = cs.workerPool.Submit(func() {
			fmt.Println(data)
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
	CodecServe(addr, multi, false, nil)
}
