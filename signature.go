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
	"github.com/ethereum/go-ethereum/crypto"
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

	valueStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", value))
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

	valueStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", value))
	valueByte, err := hex.DecodeString(string(valueStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	nonceStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", nonce))
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

	tokenIDStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", tokenID))
	tokenIDByte, err := hex.DecodeString(string(tokenIDStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	valueStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", value))
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
	AddressNodeServer     string        `json:"addressNodeServer"`
	ChainID               int64         `json:"chainId"`
	GasLimit              uint64        `json:"gasLimit"`
	WalletAddress         Address       `json:"addressWallet"`
	AddressSaleContract   Address       `json:"addressSaleContract"`
	AddressNFTContract    Address       `json:"addressNFTContract"`
	TokenID               int64         `json:"tokenId"`
	Value                 *big.Int      `json:"value"`
	VenlyClient           *venly.Client `json:"venlyClient"`
	AccessToken           string        `json:"accessToken"`
	Pincode               string        `json:"pincode"`
	WalletID              string        `json:"walletId"`
	Type                  string        `json:"type"`
	SecretType            string        `json:"secretType"`
	ContractMethodAddress Hex           `json:"contractMethodAddress"`
	To                    Address       `json:"to"`
	Nonce                 int64         `json:"nonce"`
	From                  Address       `json:"from"`
	DomainSeperator       Hex           `json:"domainSeperator"`
}

// GenerateVenlySignatureForApproveERC20 generates signature for user's wallet for approve ERC20.
func GenerateVenlySignatureForApproveERC20(ctx context.Context, venlySignature VenlySignature) (venly.SignaturesResponse, error) {
	if !venlySignature.To.IsValidAddress() {
		return venly.SignaturesResponse{}, ErrCreateSignature.New("invalid address of user's wallet")
	}
	if !venlySignature.From.IsValidAddress() {
		return venly.SignaturesResponse{}, ErrCreateSignature.New("invalid address of erc20 contract")
	}

	toStringWithZeros := createHexStringFixedLength(string(venlySignature.To[LengthHexPrefix:]))
	valueMoneyStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", venlySignature.Value))
	data := venlySignature.ContractMethodAddress + toStringWithZeros + valueMoneyStringWithZeros
	dataByte, err := hex.DecodeString(string(data[LengthHexPrefix:]))
	if err != nil {
		return venly.SignaturesResponse{}, ErrCreateSignature.Wrap(err)
	}

	functionSignatureBytes := crypto.Keccak256Hash(dataByte)

	var metaTransaction []byte
	metaTransactionFucnDescriptionBytes := crypto.Keccak256([]byte(MetaTransactionFucnDescription))
	metaTransaction = append(metaTransaction, metaTransactionFucnDescriptionBytes...)

	nonceStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", venlySignature.Nonce))
	nonceByte, err := hex.DecodeString(string(nonceStringWithZeros))
	if err != nil {
		return venly.SignaturesResponse{}, ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, nonceByte...)

	fromStringWithZeros := createHexStringFixedLength(string(venlySignature.From[LengthHexPrefix:]))
	fromByte, err := hex.DecodeString(string(fromStringWithZeros))
	if err != nil {
		return venly.SignaturesResponse{}, ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, fromByte...)
	metaTransaction = append(metaTransaction, functionSignatureBytes.Bytes()...)

	domainSeperatorStringWithZeros := createHexStringFixedLength(string(venlySignature.DomainSeperator[LengthHexPrefix:]))
	domainSeperatorByte, err := hex.DecodeString(string(domainSeperatorStringWithZeros))
	if err != nil {
		return venly.SignaturesResponse{}, ErrCreateSignature.Wrap(err)
	}

	metaTransactionBytes := crypto.Keccak256Hash(metaTransaction)

	dataSignature := crypto.Keccak256Hash([]byte(EthereumSignedMessageForApprove), domainSeperatorByte, metaTransactionBytes.Bytes())

	signatureRequest := venly.SignatureRequest{
		Type:       venlySignature.Type,
		SecretType: venlySignature.SecretType,
		WalletID:   venlySignature.WalletID,
		Data:       dataSignature.String(),
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

	toStringWithZeros := createHexStringFixedLength(string(to[LengthHexPrefix:]))
	valueMoneyStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", value))
	data := contractMethodAddress + toStringWithZeros + valueMoneyStringWithZeros
	dataByte, err := hex.DecodeString(string(data[LengthHexPrefix:]))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	functionSignatureBytes := crypto.Keccak256Hash(dataByte)

	var metaTransaction []byte
	metaTransactionFucnDescriptionBytes := crypto.Keccak256([]byte(MetaTransactionFucnDescription))
	metaTransaction = append(metaTransaction, metaTransactionFucnDescriptionBytes...)

	nonceStringWithZeros := createHexStringFixedLength(fmt.Sprintf("%x", nonce))
	nonceByte, err := hex.DecodeString(string(nonceStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, nonceByte...)

	fromStringWithZeros := createHexStringFixedLength(string(from[LengthHexPrefix:]))
	fromByte, err := hex.DecodeString(string(fromStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}
	metaTransaction = append(metaTransaction, fromByte...)
	metaTransaction = append(metaTransaction, functionSignatureBytes.Bytes()...)

	domainSeperatorStringWithZeros := createHexStringFixedLength(string(domainSeperator[LengthHexPrefix:]))
	domainSeperatorByte, err := hex.DecodeString(string(domainSeperatorStringWithZeros))
	if err != nil {
		return "", ErrCreateSignature.Wrap(err)
	}

	metaTransactionBytes := crypto.Keccak256Hash(metaTransaction)

	dataSignature := crypto.Keccak256Hash([]byte(EthereumSignedMessageForApprove), domainSeperatorByte, metaTransactionBytes.Bytes())

	signatureByte, err := crypto.Sign(dataSignature.Bytes(), privateKey)
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
