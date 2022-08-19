package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
	"log"
)

const walletVersion = byte(0x00)             // 钱包版本
const compressedPublicKeyPrefix = byte(0x02) //压缩公钥前缀
const addressChecksumLen = 4                 // 验证码长度

// 钱包
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// 初始化钱包
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

func (w Wallet) GetEthAddress() string {
	publicHash := crypto.Keccak256(w.PublicKey)
	fmt.Println("Eth:", len(publicHash))
	address := hex.EncodeToString(publicHash[len(publicHash)-20:])
	return address
}

// 得到比特币地址
func (w Wallet) GetBtcAddress() string {

	// ripemd160(sha256(publickey))
	pubKeyHash := HashPubKey(w.PublicKey)

	// 最前面添加一个字节的版本信息
	walletVersionedPayload := append([]byte{walletVersion}, pubKeyHash...)
	fmt.Println("walletVersionedPayload length", len(walletVersionedPayload))

	// 获得 sha256(sha256(versionPublickeyHash)) 四个字节
	checksum := checksum(walletVersionedPayload)

	// 拼接 walletVersionedPayload + checksumHash
	fullPayload := append(walletVersionedPayload, checksum...)

	// 进行 base58 编码，生成可视化地址
	address := base58.Encode(fullPayload)

	// 比特币地址格式：【钱包版本 + 公钥哈希 + 验证码】
	return address
}

// 得到公钥哈希
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(append([]byte{compressedPublicKeyPrefix}, pubKey[:32]...))
	RIPEMD160Hasher := ripemd160.New()
	t, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	fmt.Println("publicSHA256", t)
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	fmt.Println("publicRIPEMD160", len(publicRIPEMD160))
	return publicRIPEMD160
}

// 通过【钱包版本+公钥哈希】生成验证码
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

// 创建新的私钥、公钥
func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := crypto.S256()

	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

// 验证比特币地址
func ValidateAddress(address string) bool {
	pubKeyHash := base58.Decode(address)
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

func main() {
	wallet := NewWallet()
	fmt.Println("publicKey:", hex.EncodeToString(wallet.PublicKey))
	fmt.Println("PrivateKey:", hex.EncodeToString(wallet.PrivateKey.D.Bytes()))
	bitcoinAddress := wallet.GetBtcAddress()
	ethAddress := wallet.GetEthAddress()
	fmt.Println("ethAddress", ethAddress)
	fmt.Println("比特币地址:", string(bitcoinAddress))
	fmt.Printf("比特币地址是否有效:%v\n：", ValidateAddress(string(bitcoinAddress)))
}
