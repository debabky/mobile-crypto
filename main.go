package Denchik

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

type DenchikC struct{}

func (c DenchikC) New() *DenchikC {
	return &DenchikC{}
}

func (c *DenchikC) EdDSAKeyPairGen() (babyjub.PrivateKey, babyjub.PublicKey) {
	privateKey := babyjub.NewRandPrivKey()
	pubKey := privateKey.Public()

	return privateKey, *pubKey
}

func (c *DenchikC) PoseidonHashBytes(data []byte) []byte {
	inputBigInt := big.NewInt(0)
	inputBigInt.SetBytes(data)
	inputArr := []*big.Int{inputBigInt}

	hash, _ := poseidon.Hash(inputArr)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHash(input *big.Int) []byte {
	inputArr := []*big.Int{input}
	hash, _ := poseidon.Hash(inputArr)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHashLeftRight(left *big.Int, right *big.Int) []byte {
	input := []*big.Int{left, right}
	hash, _ := poseidon.Hash(input)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHashPoint(point *babyjub.Point) []byte {
	return c.PoseidonHashLeftRight(point.X, point.Y)
}

func (c *DenchikC) EdDSASignature(privKey babyjub.PrivateKey, signData *big.Int) *babyjub.Signature {
	signature := privKey.SignPoseidon(signData)
	return signature
}
