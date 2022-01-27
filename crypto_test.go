// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package evmsignature_test

import (
	"math/big"
	"testing"

	"github.com/BoostyLabs/evmsignature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrypto(t *testing.T) {
	var value float64 = 0.001

	t.Run("EthereumFloatToWeiBig", func(t *testing.T) {
		eth, err := evmsignature.EthereumFloatToWeiBig(value)
		require.NoError(t, err)

		ethValue := new(big.Int)
		ethValue.SetString("1000000000000000", 10)
		assert.Equal(t, eth, ethValue)
	})

	t.Run("WeiBigToEthereumFloat", func(t *testing.T) {
		weiValue := new(big.Int)
		weiValue.SetString("1000000000000000", 10)

		eth := evmsignature.WeiBigToEthereumFloat(weiValue)
		assert.Equal(t, eth, value)
	})
}
