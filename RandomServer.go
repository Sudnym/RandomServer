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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/monnand/dhkx"
	"github.com/panjf2000/gnet"
)

// map to reference for connections
var globeMap map[gnet.Conn]*dhkx.DHKey
var delimiter = regexp.MustCompile(`:`)

// codecServer used for initializing the server

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

// Make final key
func getKey(key []byte) ([]byte, *dhkx.DHKey) {
	g, _ := dhkx.GetGroup(0)
	priv, _ := g.GeneratePrivateKey(nil)
	pub := priv.Bytes()
	k, _ := g.ComputeKey(dhkx.NewPublicKey(key), priv)
	return pub, k
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

func (cs *codecServer) React(frame []byte, c gnet.Conn) (out []byte, action gnet.Action) {
	if cs.async {
		data := append([]byte{}, frame...)
		datum := delimiter.Split(string(data), 2)
		selector := data[:3]
		message := datum[1]
		switch selector {
		case []byte{0x000C}:
			_ = cs.workerPool.Submit(func() {
				key := []byte(message)
				publickey, privkey := getKey(key)
				globeMap[c] = privkey
				c.AsyncWrite(publickey)
			})
			return
		case []byte{0x000B}:
			_ = cs.workerPool.Submit(func() {
				fmt.Println(decrypt([]byte(message), globeMap[c]))
			})
			return
		}
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
