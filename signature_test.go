// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package evmsignature_test

import (
	"math/big"
	"testing"

	"github.com/BoostyLabs/evmsignature"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvmsignature(t *testing.T) {
	data1 := map[string]string{
		"addressWallet":   "0xe2B32824733d350845c056CedD73c491FC4C1585",
		"addressContract": "0x0c80417acb4b309725de29b1d950bca974120996",
		"privateKey":      "5aefce0a2d473f59578fa7dee6a122d6509af1e0f79fcbee700dfcfeddabe4cc",
		"signature":       "707fb93c61be8d54c6d1fdf4b83c8642831c480194f7cc93ebdd6fe1ac7474ae63efd077cf6398bf00dc0f7ea96be9f3f9a05dfac1382c4d2f1bb11ec46148491b",
	}

	data2 := map[string]string{
		"addressWallet":   "0xe2B32824733d350845c056CedD73c491FC4C1585",
		"addressContract": "0x02a061be81ee0d7dbbd972bc7edee30b7b102a40",
		"privateKey":      "5aefce0a2d473f59578fa7dee6a122d6509af1e0f79fcbee700dfcfeddabe4cc",
		"signature":       "c2ab46d5981fe2fe951a63240af99a639ca13ea9afa1ee640d418690eae178215571ef9d318cc5b79d2c9e184e036f513aea7edcd6517cca75c4790d9ead45fc1b",
	}
	var tokenID2 int64 = 2

	data3 := map[string]string{
		"addressWallet":   "0xb2cdC7EB2F9d2E629ee97BB91700622A42e688b8",
		"addressContract": "0xde07015be3E663954D514418B4014c3b829D212b",
		"privateKey":      "5aefce0a2d473f59578fa7dee6a122d6509af1e0f79fcbee700dfcfeddabe4cc",
		"signature":       "53f7f1e623364fa4f1bd6e7df67a66edcc06cba01462193d397bbe72fcdba31f04e50d9f65e387be1ea2351110166ad2cb882ccc28be05725e6877645941a3471b",
	}
	var value3 = new(big.Int)
	value3.SetString("5000000000000000000", 10)
	var nonce3 int64 = 0

	data4 := map[string]string{
		"addressWallet":       "0xe2B32824733d350845c056CedD73c491FC4C1585",
		"addressSaleContract": "0x2D1526bad5E59eBc8fc1b2eCBC06dbC8f856Cd2D",
		"addressNFTContract":  "0x674cd2ab624a3eD4f93cbB3d25399cd987B6F564",
		"privateKey":          "5aefce0a2d473f59578fa7dee6a122d6509af1e0f79fcbee700dfcfeddabe4cc",
		"signature":           "ec12bc59894c3964187ec8a0ef15f94ae8a84a1ce943d58d7633ba451ef81aa04689669f8d16e249ddb0afafacec5f231b1a41acecc2884d00ca1982235b9ed71c",
	}
	var tokenID4 int64 = 3
	var value4 = new(big.Int)
	value4.SetString("100000000000000000", 10)

	data5 := map[string]string{
		"contractMethodAddress": "0x095ea7b3",
		"to":                    "0xfeA3995326f0C08d9a385C5AD344b87A384B5d3A",
		"from":                  "0x4604F4045bb2b2d998dEd660081eb6ebC19C9f1e",
		"domainSeperator":       "0x2739d6640de1503427ab7c5bd20094483387d4f8de3af1aeb1cfbf826f1b5b30",
		"privateKey":            "5aefce0a2d473f59578fa7dee6a122d6509af1e0f79fcbee700dfcfeddabe4cc",
		"signature":             "89e91e4dccae549130688ee82f2f8ee9a365412929e7922751dde082dc9d0fa849051302294e8f3b2583f00acfb8f0a91eee3c5d42dffb512b81968b8e7258e01b",
	}
	var value5 = new(big.Int)
	value5.SetString("1000000000", 10)
	var nonce5 int64 = 0

	t.Run("GenerateSignature", func(t *testing.T) {
		privateKeyECDSA, err := crypto.HexToECDSA(data1["privateKey"])
		require.NoError(t, err)

		signature, err := evmsignature.GenerateSignature(
			evmsignature.Address(data1["addressWallet"]),
			evmsignature.Address(data1["addressContract"]),
			privateKeyECDSA,
		)
		require.NoError(t, err)
		assert.Equal(t, signature, evmsignature.Signature(data1["signature"]))
	})

	t.Run("GenerateSignatureWithValue", func(t *testing.T) {
		privateKeyECDSA, err := crypto.HexToECDSA(data2["privateKey"])
		require.NoError(t, err)

		signature, err := evmsignature.GenerateSignatureWithValue(
			evmsignature.Address(data2["addressWallet"]),
			evmsignature.Address(data2["addressContract"]),
			tokenID2,
			privateKeyECDSA,
		)
		require.NoError(t, err)
		assert.Equal(t, signature, evmsignature.Signature(data2["signature"]))
	})

	t.Run("GenerateSignatureWithValueAndNonce", func(t *testing.T) {
		privateKeyECDSA, err := crypto.HexToECDSA(data3["privateKey"])
		require.NoError(t, err)

		signature, err := evmsignature.GenerateSignatureWithValueAndNonce(
			evmsignature.Address(data3["addressWallet"]),
			evmsignature.Address(data3["addressContract"]),
			value3,
			nonce3,
			privateKeyECDSA,
		)
		require.NoError(t, err)
		assert.Equal(t, signature, evmsignature.Signature(data3["signature"]))
	})

	t.Run("GenerateSignatureWithTokenIDAndValue", func(t *testing.T) {
		privateKeyECDSA, err := crypto.HexToECDSA(data4["privateKey"])
		require.NoError(t, err)

		signature, err := evmsignature.GenerateSignatureWithTokenIDAndValue(
			evmsignature.Address(data4["addressWallet"]),
			evmsignature.Address(data4["addressSaleContract"]),
			evmsignature.Address(data4["addressNFTContract"]),
			tokenID4,
			value4,
			privateKeyECDSA,
		)
		require.NoError(t, err)
		assert.Equal(t, signature, evmsignature.Signature(data4["signature"]))
	})

	t.Run("GenerateSignatureForApproveERC20", func(t *testing.T) {
		privateKeyECDSA, err := crypto.HexToECDSA(data5["privateKey"])
		require.NoError(t, err)

		signature, err := evmsignature.GenerateSignatureForApproveERC20(
			evmsignature.Hex(data5["contractMethodAddress"]),
			evmsignature.Address(data5["to"]),
			value5,
			nonce5,
			evmsignature.Address(data5["from"]),
			evmsignature.Hex(data5["domainSeperator"]),
			privateKeyECDSA,
		)
		require.NoError(t, err)
		assert.Equal(t, signature, evmsignature.Signature(data5["signature"]))
	})
}
