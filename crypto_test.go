// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package evmsignature_test

import (
	"math/big"
	"testing"

	"github.com/BoostyLabs/evmsignature"
	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	var value float64 = 0.001

	t.Run("EthereumToWei", func(t *testing.T) {
		eth := evmsignature.EthereumToWei(value)

		ethValue := new(big.Int)
		ethValue.SetString("1000000000000000", 10)
		assert.Equal(t, eth, ethValue)
	})
}
