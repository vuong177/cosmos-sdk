package bls12381

import (
	"bytes"
	"fmt"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/prysmaticlabs/prysm/v4/config/params"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls/blst"
)

var (
	KeyType = "bls12381"

	// PubKeySize is the number of bytes in an bls12-381 public key.
	PubKeySize = params.BeaconConfig().BLSPubkeyLength
)

// Address is the SHA256-20 of the raw pubkey bytes.
func (pubKey PubKey) Address() crypto.Address {
	return crypto.Address(tmhash.SumTruncated(pubKey.Bytes()[:]))
}

// Bytes returns the byte representation of the PubKey.
func (pubKey PubKey) Bytes() []byte {
	return pubKey.Key
}

// Equals - checks that two public keys are the same time
// Runs in constant time based on length of the keys.
// TODO: check this
func (pubKey PubKey) Equals(other cryptotypes.PubKey) bool {
	return bytes.Equal(pubKey.Bytes()[:], other.Bytes()[:])
}

func (pubKey PubKey) VerifySignature(msg []byte, sigBytes []byte) bool {
	signature, err := blst.SignatureFromBytes(sigBytes)
	if err != nil {
		return false
	}
	blstPubKey, err := blst.PublicKeyFromBytes(pubKey.Key)
	if err != nil {
		return false
	}

	if err != nil {
		return false
	}

	return signature.Verify(blstPubKey, msg)
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBLS12-381{%X}", pubKey.Key)
}

func (pubKey PubKey) Type() string {
	return KeyType
}
