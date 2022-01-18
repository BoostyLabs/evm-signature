// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package evmsignature

import (
	"context"
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/zeebo/errs"
)

// ErrDeployContract indicates that an error occurred while deploying a contract.
var ErrDeployContract = errs.Class("deploy contract error")

// ContractConfig describes values required to deploy contact.
type ContractConfig struct {
	AddressNodeServer string   `json:"addressNodeServer"`
	PrivateKey        string   `json:"privateKey"`
	ChainID           *big.Int `json:"chainID"`
	GasLimit          uint64   `json:"gasLimit"`
}

// DeployNFTContract deploys nft contract for each collection nfts.
func DeployNFTContract(ctx context.Context, config ContractConfig, deployContract func(auth *bind.TransactOpts, client *ethclient.Client) (common.Address, error)) (common.Address, error) {
	client, err := ethclient.Dial(config.AddressNodeServer)
	if err != nil {
		return common.Address{}, ErrDeployContract.Wrap(err)
	}

	privateKeyECDSA, err := crypto.HexToECDSA(config.PrivateKey)
	if err != nil {
		return common.Address{}, ErrDeployContract.Wrap(err)
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return common.Address{}, ErrDeployContract.New("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return common.Address{}, ErrDeployContract.Wrap(err)
	}

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Address{}, ErrDeployContract.Wrap(err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(privateKeyECDSA, config.ChainID)
	if err != nil {
		return common.Address{}, ErrDeployContract.Wrap(err)
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)              // in wei
	auth.GasLimit = uint64(config.GasLimit) // in units
	auth.GasPrice = gasPrice

	address, err := deployContract(auth, client)
	return address, ErrDeployContract.Wrap(err)
}
