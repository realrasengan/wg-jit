/* SPDX-License-Identifier: MIT
**
** Copyright (c) 2024 Andrew Lee <andrew@joseon.com>
*/
package main

import (
  "encoding/binary"
  "encoding/base64"
  "crypto/hmac"
  "bytes"
  "strings"
  "strconv"
  "flag"
  "fmt"
  "hash"
  "log"
  "os"

  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "golang.org/x/crypto/poly1305"
  "golang.org/x/crypto/blake2s"
  "golang.org/x/crypto/curve25519"
  "golang.org/x/crypto/chacha20poly1305"
)

const HELLO_PACKET_SIZE = 148
const MAX_PACKET_SIZE = 1600

type WireGuardInitiationMessage struct {
    MessageType uint8
    Reserved    [3]byte
    Sender      uint32
    Ephemeral   [32]byte
    Static      [32 + poly1305.TagSize]byte
    Timestamp   [12 + poly1305.TagSize]byte
    MAC1        [blake2s.Size128]byte
    MAC2        [blake2s.Size128]byte
}

var (
  InitialChainKey [blake2s.Size]byte
  InitialHash     [blake2s.Size]byte
  ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
  WGconstruction := "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
  WGidentifier := "WireGuard v1 zx2c4 Jason@zx2c4.com"
  InitialChainKey = blake2s.Sum256([]byte(WGconstruction))
  mixHash(&InitialHash, &InitialChainKey, []byte(WGidentifier));
}

func main() {
  const snapLen = int32(MAX_PACKET_SIZE)
  var (
    privateKeyBase64 string
    ifaceName        string
    wireguardPort     int
  )

  flag.StringVar(&privateKeyBase64, "privatekey", "", "Base64 encoded private key")
  flag.StringVar(&ifaceName, "iface", "", "Interface to eBPF Filter")
  flag.IntVar(&wireguardPort, "port", 51820, "Port of your WG")

  flag.Parse();

  if privateKeyBase64 == "" {
    flag.Usage()
    os.Exit(1)
  }
  if ifaceName == "" {
    flag.Usage()
    os.Exit(1)
  }
  if wireguardPort == 0 {
    flag.Usage()
    os.Exit(1)
  }
  handle, err := pcap.OpenLive(ifaceName, snapLen, false, pcap.BlockForever)
  if err != nil {
    log.Fatalf("Error opening device %s: %v", ifaceName, err)
  }
  defer handle.Close()

  portStr := strconv.Itoa(wireguardPort)
  filter := fmt.Sprintf("udp and port %s and udp[8] = 1", portStr)
  err = handle.SetBPFFilter(filter)
  if err != nil {
    log.Fatalf("Error setting BPF filter: %v", err)
  }

  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    processPacket(packet, privateKeyBase64)
  }
}

func decodeWireGuardMessage(payload []byte) (*WireGuardInitiationMessage, error) {
  if len(payload) < HELLO_PACKET_SIZE {
    return nil, nil
  }

  msg := &WireGuardInitiationMessage{}
  reader := bytes.NewReader(payload)

  err := binary.Read(reader, binary.LittleEndian, msg)
  if err != nil {
    return nil, fmt.Errorf("failed to decode WireGuard message: %v", err)
  }

  return msg, nil
}

func processPacket(packet gopacket.Packet, privateKeyBase64 string) {
  udpLayer := packet.Layer(layers.LayerTypeUDP)
  if udpLayer == nil {
    return
  }
  udp, _ := udpLayer.(*layers.UDP)

  if udp.DstPort != 51820 && udp.SrcPort != 51820 {
    return
  }

  payload := udp.Payload
  msg, err := decodeWireGuardMessage(payload)
  if err != nil {
    log.Printf("Failed to decode WireGuard message: %v\n", err)
    return
  }

  publicKey, err := analyzePacket(msg, privateKeyBase64)
  if err != nil {
    log.Printf("Failed to analyze packet: %v\n", err)
    return
  }
  publicKeyBase64Str := base64.StdEncoding.EncodeToString(publicKey[:])

  // JIT Here with publicKeyBase64Str which is the Base64 encoded Static Public Key of the Peer :-)
  fmt.Printf("Static Public Key is: %s\n",publicKeyBase64Str);
}

func analyzePacket(msg *WireGuardInitiationMessage, privateKeyBase64 string)(*[32]byte, error) {
  var (
    hash     [blake2s.Size]byte
    chainKey [blake2s.Size]byte
  )

  privateKeyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyBase64))
  if err != nil {
    log.Fatalf("Failed to decode private key from base64: %v", err)
  }

  var privateKey [32]byte
  copy(privateKey[:], privateKeyBytes[:32])

  publicKeySlice, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
  if err != nil {
    return nil, fmt.Errorf("failed to generate public key from private key: %v", err)
  }

  var publicKey [32]byte
  copy(publicKey[:], publicKeySlice)

  mixHash(&hash, &InitialHash, publicKey[:])
  mixHash(&hash, &hash, msg.Ephemeral[:]);
  mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:]);

  var key [chacha20poly1305.KeySize]byte
  sharedSecret, err := curve25519.X25519(privateKeyBytes, msg.Ephemeral[:])
  if err != nil {
    log.Fatalf("Failed to compute shared secret: %v", err)
  }
  KDF2(&chainKey, &key, chainKey[:], sharedSecret[:])
  aead, err := chacha20poly1305.New(key[:])
  if err != nil {
    return nil, fmt.Errorf("failed to create AEAD: %v", err)
  }

  var data [32]byte
  decryptedStatic, err := aead.Open(data[:0], ZeroNonce[:], msg.Static[:], hash[:])
  if err != nil {
    return nil, fmt.Errorf("failed to decrypt static key: %v", err)
  }

  var decryptedStaticArray [32]byte
  copy(decryptedStaticArray[:], decryptedStatic)

  return &decryptedStaticArray, nil
}

/* From noise-helpers.go of wireguard-go by Jason Donenfeld */
func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}
func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}
func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}
func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}
func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}
func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}
