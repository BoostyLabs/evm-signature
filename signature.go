// Copyright (C) 2021 Creditor Corp. Group.
// See LICENSE for copying information.

package evmsignature

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/BoostyLabs/venly"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/zeebo/errs"
)

// ErrCreateSignature indicates that an error occurred while creating a signature.
var ErrCreateSignature = errs.Class("create signature error")

// CreateSignature entity describes values for create signature.
type CreateSignature struct {
	Values     [][]byte
	PrivateKey *ecdsa.PrivateKey
}

// Signature defines signature type.
type Signature string

// EthereumSignedMessage defines message for signature.
const EthereumSignedMessage string = "\x19Ethereum Signed Message:\n"

// MetaTransactionFucnDescription defines name and parameters MetaTransaction function.
const MetaTransactionFucnDescription string = "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"

// EthereumSignedMessageForApprove defines signature message for approve.
const EthereumSignedMessageForApprove string = "\x19\x01"

// SignHash is a function that calculates a hash for the given message.
func SignHash(data []byte) []byte {
	msg := fmt.Sprintf(EthereumSignedMessage+"%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// GenerateSignature generates signature for user's wallet.
func GenerateSignature(addressWallet Address, addressContract Address, privateKey *ecdsa.PrivateKey) (Signature, error) {
	var values [][]byte
	if !addressWallet.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !addressContract.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of contract")
	}

	addressWalletByte, err := hex.DecodeString(string(addressWallet)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	addressContractByte, err := hex.DecodeString(string(addressContract)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	values = append(values, addressWalletByte, addressContractByte)
	createSignature := CreateSignature{
		Values:     values,
		PrivateKey: privateKey,
	}

	signatureByte, err := makeSignature(createSignature)
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	signature, err := reformSignature(signatureByte)

	return signature, ErrCreateSignature.Wrap(err)
}

// GenerateSignatureWithValue generates signature for user's wallet with value.
func GenerateSignatureWithValue(addressWallet Address, addressContract Address, value int64, privateKey *ecdsa.PrivateKey) (Signature, error) {
	var values [][]byte
	if !addressWallet.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !addressContract.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of contract")
	}

	addressWalletByte, err := hex.DecodeString(string(addressWallet)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	addressContractByte, err := hex.DecodeString(string(addressContract)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	valueStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", value))
	valueByte, err := hex.DecodeString(string(valueStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	values = append(values, addressWalletByte, addressContractByte, valueByte)
	createSignature := CreateSignature{
		Values:     values,
		PrivateKey: privateKey,
	}

	signatureByte, err := makeSignature(createSignature)
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	signature, err := reformSignature(signatureByte)

	return signature, ErrCreateSignature.Wrap(err)
}

// GenerateSignatureWithValueAndNonce generates signature for user's wallet with value and nonce.
func GenerateSignatureWithValueAndNonce(addressWallet Address, addressContract Address, value *big.Int, nonce int64, privateKey *ecdsa.PrivateKey) (Signature, error) {
	var values [][]byte
	if !addressWallet.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !addressContract.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of contract")
	}

	addressWalletByte, err := hex.DecodeString(string(addressWallet)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	addressContractByte, err := hex.DecodeString(string(addressContract)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	valueStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", value))
	valueByte, err := hex.DecodeString(string(valueStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	nonceStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", nonce))
	nonceByte, err := hex.DecodeString(string(nonceStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	values = append(values, addressWalletByte, addressContractByte, valueByte, nonceByte)
	createSignature := CreateSignature{
		Values:     values,
		PrivateKey: privateKey,
	}

	signatureByte, err := makeSignature(createSignature)
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	signature, err := reformSignature(signatureByte)

	return signature, ErrCreateSignature.Wrap(err)
}

// GenerateSignatureWithTokenIDAndValue generates signature for user's wallet with tokenID and value.
func GenerateSignatureWithTokenIDAndValue(addressWallet Address, addressSaleContract Address, addressNFTContract Address, tokenID int64, value *big.Int, privateKey *ecdsa.PrivateKey) (Signature, error) {
	var values [][]byte
	if !addressWallet.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !addressSaleContract.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of sale contract")
	}
	if !addressNFTContract.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of nft contract")
	}

	addressWalletByte, err := hex.DecodeString(string(addressWallet)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	addressSaleContractByte, err := hex.DecodeString(string(addressSaleContract)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	addressNFTContractByte, err := hex.DecodeString(string(addressNFTContract)[LengthHexPrefix:])
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	tokenIDStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", tokenID))
	tokenIDByte, err := hex.DecodeString(string(tokenIDStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	valueStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", value))
	valueByte, err := hex.DecodeString(string(valueStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	values = append(values, addressWalletByte, addressSaleContractByte, addressNFTContractByte, tokenIDByte, valueByte)
	createSignature := CreateSignature{
		Values:     values,
		PrivateKey: privateKey,
	}

	signatureByte, err := makeSignature(createSignature)
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	signature, err := reformSignature(signatureByte)

	return signature, ErrCreateSignature.Wrap(err)
}

// VenlySignature defines the values required to create a sigturature using venly.
type VenlySignature struct {
	To                    common.Address `json:"to"`
	Value                 *big.Int       `json:"value"`
	ContractMethodAddress Hex            `json:"contractMethodAddress"`
	Nonce                 int64          `json:"nonce"`
	From                  common.Address `json:"from"`
	Type                  string         `json:"type"`
	SecretType            string         `json:"secretType"`
	WalletID              string         `json:"walletId"`
	Pincode               string         `json:"pincode"`
	VenlyClient           *venly.Client  `json:"venlyClient"`
	AccessToken           string         `json:"accessToken"`
}

// TypedDataDomain represents the domain part of an EIP-712 message.
type TypedDataDomain struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	VerifyingContract string `json:"verifyingContract"`
	Salt              string `json:"salt"`
}

// TypedData is a type to encapsulate EIP-712 typed messages.
type TypedData struct {
	Types       apitypes.Types            `json:"types"`
	PrimaryType string                    `json:"primaryType"`
	Domain      TypedDataDomain           `json:"domain"`
	Message     apitypes.TypedDataMessage `json:"message"`
}

// DomainVersion indicated that version of domain for approve is 1.
const DomainVersion string = "1"

// WrappedEther defines wrapped ether type.
type WrappedEther string

const (
	// WrappedEtherName defines name of wrapped ether contract.
	WrappedEtherName WrappedEther = "Wrapped Ether"
	// WrappedEtherAddress defines address of wrapped ether contract.
	WrappedEtherAddress WrappedEther = "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619"
)

// GenerateVenlySignatureForApproveERC20 generates signature for user's wallet for approve ERC20.
func GenerateVenlySignatureForApproveERC20(ctx context.Context, venlySignature VenlySignature) (venly.SignaturesResponse, error) {
	if !common.IsHexAddress(venlySignature.To.Hex()) {
		return venly.SignaturesResponse{}, ErrCreateSignature.New("invalid address of erc721 contract")
	}
	if !common.IsHexAddress(venlySignature.From.Hex()) {
		return venly.SignaturesResponse{}, ErrCreateSignature.New("invalid address of user's wallet")
	}

	toStringWithZeros := CreateHexStringFixedLength(string(venlySignature.To[LengthHexPrefix:]))
	valueMoneyStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", venlySignature.Value))
	data := venlySignature.ContractMethodAddress + toStringWithZeros + valueMoneyStringWithZeros

	signerData := TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "verifyingContract", Type: "address"},
				{Name: "salt", Type: "bytes32"},
			},
			"MetaTransaction": []apitypes.Type{
				{Name: "nonce", Type: "uint256"},
				{Name: "from", Type: "address"},
				{Name: "functionSignature", Type: "bytes"},
			},
		},
		PrimaryType: "MetaTransaction",
		Domain: TypedDataDomain{
			Name:              string(WrappedEtherName),
			Version:           DomainVersion,
			VerifyingContract: string(WrappedEtherAddress),
			Salt:              "0x" + string(CreateHexStringFixedLength(fmt.Sprintf("%x", ChainIDMatic))),
		},
		Message: apitypes.TypedDataMessage{
			"nonce":             venlySignature.Nonce,
			"from":              venlySignature.From,
			"functionSignature": data,
		},
	}

	signatureRequest := venly.SignatureRequest{
		Type:       venlySignature.Type,
		SecretType: venlySignature.SecretType,
		WalletID:   venlySignature.WalletID,
		Data:       signerData,
	}

	signaturesRequest := venly.SignaturesRequest{
		Pincode:          venlySignature.Pincode,
		SignatureRequest: signatureRequest,
	}

	signaturesResponse, err := venlySignature.VenlyClient.Signatures(ctx, venlySignature.AccessToken, signaturesRequest)
	return signaturesResponse, ErrCreateSignature.Wrap(err)
}

// GenerateSignatureForApproveERC20 generates signature for user's wallet for approve ERC20.
func GenerateSignatureForApproveERC20(contractMethodAddress Hex, to Address, value *big.Int, nonce int64, from Address, domainSeperator Hex, privateKey *ecdsa.PrivateKey) (Signature, error) {
	if !to.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !from.IsValidAddress() {
		return "", ErrCreateSignature.New("invalid address of erc20 contract")
	}

	toStringWithZeros := CreateHexStringFixedLength(string(to[LengthHexPrefix:]))
	valueMoneyStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", value))
	data := contractMethodAddress + toStringWithZeros + valueMoneyStringWithZeros
	dataByte, err := hex.DecodeString(string(data[LengthHexPrefix:]))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	functionSignatureBytes := crypto.Keccak256Hash(dataByte)

	var metaTransaction []byte
	metaTransactionFucnDescriptionBytes := crypto.Keccak256([]byte(MetaTransactionFucnDescription))
	metaTransaction = append(metaTransaction, metaTransactionFucnDescriptionBytes...)

	nonceStringWithZeros := CreateHexStringFixedLength(fmt.Sprintf("%x", nonce))
	nonceByte, err := hex.DecodeString(string(nonceStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, nonceByte...)

	fromStringWithZeros := CreateHexStringFixedLength(string(from[LengthHexPrefix:]))
	fromByte, err := hex.DecodeString(string(fromStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, fromByte...)
	metaTransaction = append(metaTransaction, functionSignatureBytes.Bytes()...)
	metaTransactionBytes := crypto.Keccak256Hash(metaTransaction)

	domainSeperatorStringWithZeros := CreateHexStringFixedLength(string(domainSeperator[LengthHexPrefix:]))
	domainSeperatorByte, err := hex.DecodeString(string(domainSeperatorStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	dataSignature := crypto.Keccak256Hash([]byte(EthereumSignedMessageForApprove), domainSeperatorByte, metaTransactionBytes.Bytes())

	signatureByte, err := crypto.Sign(dataSignature.Bytes(), privateKey)
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	signature, err := reformSignature(signatureByte)

	return signature, ErrCreateSignature.Wrap(err)
}

// makeSignatureWithToken makes signature from addresses, private key and token id.
func makeSignature(createSignature CreateSignature) ([]byte, error) {
	var allValues []byte
	for _, value := range createSignature.Values {
		allValues = append(allValues, value...)
	}
	dataSignature := SignHash(crypto.Keccak256Hash(allValues).Bytes())
	signature, err := crypto.Sign(dataSignature, createSignature.PrivateKey)
	return signature, ErrCreateSignature.Wrap(err)
}

// reformSignature reforms last two byte of signature from 00, 01 to 1b, 1c.
func reformSignature(signatureByte []byte) (Signature, error) {
	signatureWithoutEnd := string(signatureByte)[:len(signatureByte)-1]
	signatureString := hex.EncodeToString(signatureByte)
	signatureLastSymbol := signatureString[len(signatureString)-1:]

	if signatureLastSymbol == fmt.Sprintf("%d", PrivateKeyVZero) {
		return Signature(hex.EncodeToString(append([]byte(signatureWithoutEnd), []byte{byte(PrivateKeyVTwentySeven)}...))), nil
	}

	if signatureLastSymbol == fmt.Sprintf("%d", PrivateKeyVOne) {
		return Signature(hex.EncodeToString(append([]byte(signatureWithoutEnd), []byte{byte(PrivateKeyVTwentyEight)}...))), nil
	}

	return "", ErrCreateSignature.New("error private key format")
}
