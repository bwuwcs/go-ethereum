package tests

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func toBig(v string) *big.Int {
	b, ok := new(big.Int).SetString(v, 10)
	if !ok {
		panic("bad big.Int string")
	}
	return b
}

func TestARLP(t *testing.T) {

	items := []interface{}{
		uint64(333013),
		common.FromHex("0xfb8f2d4ae37582cb7ae307196d6e789b7f8ccb665d34ac77000000000"),
		toBig("37788494754494904754064770007423869431791776276838145493898599251081614922324"),
		[]interface{}{
			uint64(131231012),
			"交易扩展信息",
		},
	}

	b, err := rlp.EncodeToBytes(items)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("RLP编码输出：\n", common.Bytes2Hex(b))

	for i, v := range items {
		b, err := rlp.EncodeToBytes(v)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("items[%d]=RLP(%v)=%s\n", i, v, common.Bytes2Hex(b))
		if list, ok := v.([]interface{}); ok {
			for i, v := range list {
				b, err := rlp.EncodeToBytes(v)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Printf("\t\t [%d]=RLP(%v)=%s\n", i, v, common.Bytes2Hex(b))
			}
		}
	}
}
