package bls12381

import (
	"bytes"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/prysmaticlabs/prysm/v4/crypto/bls/blst"
)

var (
	_ cryptotypes.PrivKey  = &PrivKey{}
	_ codec.AminoMarshaler = &PrivKey{}
)
var (
	PrivKeyName = "tendermint/PrivKeyBls12381"
	PubKeyName  = "tendermint/PubKeyBls12381"
)

// Sign never return err
func (priv PrivKey) Sign(msg []byte) ([]byte, error) {
	blstSecretKey, _ := blst.SecretKeyFromBytes(priv.Secret)
	return blstSecretKey.Sign(msg).Marshal(), nil
}

func (priv PrivKey) Bytes() []byte {
	return priv.Secret
}

// Equals - you probably don't need to use this.
// Runs in constant time based on length of the keys.
func (privKey PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return bytes.Equal(privKey.Bytes()[:], other.Bytes()[:])
}

func (privKey PrivKey) PubKey() cryptotypes.PubKey {
	blstSecretKey, _ := blst.SecretKeyFromBytes(privKey.Secret)
	return &PubKey{Key: blstSecretKey.PublicKey().Marshal()}
}

func (privKey PrivKey) Type() string {
	return PrivKeyName
}

// MarshalAmino overrides Amino binary marshalling.
func (privKey PrivKey) MarshalAmino() ([]byte, error) {
	return privKey.Secret, nil
}

// UnmarshalAmino overrides Amino binary marshalling.
func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {

	privKey.Secret = bz

	return nil
}

// MarshalAminoJSON overrides Amino JSON marshalling.
func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) {
	// When we marshal to Amino JSON, we don't marshal the "key" field itself,
	// just its contents (i.e. the key bytes).
	return privKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshalling.
func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error {
	return privKey.UnmarshalAmino(bz)
}
