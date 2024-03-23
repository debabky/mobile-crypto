package main

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

type Crypto struct{}

func (c *Crypto) EdDSAKeyPairGen() (babyjub.PrivateKey, babyjub.PublicKey) {
	privateKey := babyjub.NewRandPrivKey()
	pubKey := privateKey.Public()

	return privateKey, *pubKey
}

func (c *Crypto) PoseidonHashBytes(data []byte) *big.Int {
	inputBigInt := big.NewInt(0)
	inputBigInt.SetBytes(data)
	inputArr := []*big.Int{inputBigInt}

	hash, _ := poseidon.Hash(inputArr)

	return hash
}

func (c *Crypto) PoseidonHash(input *big.Int) *big.Int {
	inputArr := []*big.Int{input}
	hash, _ := poseidon.Hash(inputArr)

	return hash
}

func (c *Crypto) PoseidonHashLeftRight(left *big.Int, right *big.Int) *big.Int {
	input := []*big.Int{left, right}
	hash, _ := poseidon.Hash(input)

	return hash
}

func (c *Crypto) PoseidonHashPoint(point *babyjub.Point) *big.Int {
	return c.PoseidonHashLeftRight(point.X, point.Y)
}

func (c *Crypto) EdDSASignature(privKey babyjub.PrivateKey, signData *big.Int) *babyjub.Signature {
	signature := privKey.SignPoseidon(signData)
	return signature
}
