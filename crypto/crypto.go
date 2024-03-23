package crypto

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func EdDSAKeyPairGen() (babyjub.PrivateKey, babyjub.PublicKey) {
	privateKey := babyjub.NewRandPrivKey()
	pubKey := privateKey.Public()

	return privateKey, *pubKey
}

func PoseidonHashBytes(data []byte) *big.Int {
	inputBigInt := big.NewInt(0)
	inputBigInt.SetBytes(data)
	inputArr := []*big.Int{inputBigInt}

	hash, _ := poseidon.Hash(inputArr)

	return hash
}

func PoseidonHash(input *big.Int) *big.Int {
	inputArr := []*big.Int{input}
	hash, _ := poseidon.Hash(inputArr)

	return hash
}

func PoseidonHashLeftRight(left *big.Int, right *big.Int) *big.Int {
	input := []*big.Int{left, right}
	hash, _ := poseidon.Hash(input)

	return hash
}

func PoseidonHashPoint(point *babyjub.Point) *big.Int {
	return PoseidonHashLeftRight(point.X, point.Y)
}

func EdDSASignature(privKey babyjub.PrivateKey, signData *big.Int) *babyjub.Signature {
	signature := privKey.SignPoseidon(signData)
	return signature
}
