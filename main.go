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

func (c *DenchikC) EdDSAKeyPairGen() ([]byte, []byte, []byte) {
	privateKey := babyjub.NewRandPrivKey()
	pubKey := privateKey.Public()

	return privateKey[:], pubKey.X.Bytes(), pubKey.Y.Bytes()
}

func (c *DenchikC) PoseidonHashBytes(data []byte) []byte {
	inputBigInt := big.NewInt(0)
	inputBigInt.SetBytes(data)
	inputArr := []*big.Int{inputBigInt}

	hash, _ := poseidon.Hash(inputArr)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHash(input []byte) []byte {
	inputArr := []*big.Int{new(big.Int).SetBytes(input)}
	hash, _ := poseidon.Hash(inputArr)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHashLeftRight(left, right []byte) []byte {
	input := []*big.Int{new(big.Int).SetBytes(left), new(big.Int).SetBytes(right)}
	hash, _ := poseidon.Hash(input)

	return hash.Bytes()
}

func (c *DenchikC) PoseidonHashPoint(x, y []byte) []byte {
	return c.PoseidonHashLeftRight(x, y)
}

func (c *DenchikC) EdDSASignature(privKeyBytes []byte, signData []byte) ([]byte, []byte, []byte) {
	privKey := babyjub.PrivateKey{}
	copy(privKey[:], privKeyBytes)

	signature := privKey.SignPoseidon(new(big.Int).SetBytes(signData))
	return signature.R8.X.Bytes(), signature.R8.Y.Bytes(), signature.S.Bytes()
}
