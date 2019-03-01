package scripts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/ripemd160"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/btcutil/scripts"
)

func HashPubKey(pk *btcec.PublicKey) []byte {
	h1 := sha256.Sum256(pk.SerializeCompressed())
	return ripemd160.New().Sum(h1[:])
}

func TestInterpreter(t *testing.T) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	hexPubKey := hex.EncodeToString(pubKey.SerializeCompressed())
	hexPubKeyHash := hex.EncodeToString(HashPubKey(pubKey))

	signed := sha256.Sum256([]byte{42})
	sig, err := privKey.Sign(signed[:])
	require.NoError(t, err)

	hexSig := hex.EncodeToString(sig.Serialize())

	t.Run("Validate()", func(t *testing.T) {
		t.Run("Returns an interpreter", func(t *testing.T) {
			i, err := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("OP_DUP OP_HASH160 %s OP_EQUAL OP_CHECKSIG", hexPubKeyHash)).
				WithUnlockScript(fmt.Sprintf("%s %s", hexSig, hexPubKey)).
				Validate()

			require.NoError(t, err)
			assert.NotNil(t, i)
		})
	})
}
