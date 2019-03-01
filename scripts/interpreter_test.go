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

func createSig(t *testing.T, tx []byte) (string, string, string) {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	hexPubKey := hex.EncodeToString(pubKey.SerializeCompressed())

	h := sha256.Sum256(pubKey.SerializeCompressed())
	pubKeyHash := ripemd160.New().Sum(h[:])
	hexPubKeyHash := hex.EncodeToString(pubKeyHash)

	sig, err := privKey.Sign(tx)
	require.NoError(t, err)

	hexSig := hex.EncodeToString(sig.Serialize())

	return hexPubKeyHash, hexPubKey, hexSig
}

func TestInterpreter(t *testing.T) {
	t.Run("Validate()", func(t *testing.T) {
		t.Run("Returns an interpreter", func(t *testing.T) {
			i, err := scripts.NewTxInputInterpreter().
				WithLockScript("OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG").
				WithUnlockScript("<sig> <pubKey>").
				Validate()

			require.NoError(t, err)
			assert.NotNil(t, i)
		})
	})

	t.Run("Evaluate()", func(t *testing.T) {
		t.Run("Valid numeric script", func(t *testing.T) {
			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript("OP_ADD 5 OP_EQUAL").
				WithUnlockScript("2 3").
				Validate()

			ok := i.Evaluate()
			assert.True(t, ok)
		})

		t.Run("Invalid numeric script", func(t *testing.T) {
			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript("OP_ADD 5 OP_EQUALVERIFY OP_TRUE").
				WithUnlockScript("2 1").
				Validate()

			ok := i.Evaluate()
			assert.False(t, ok)
		})

		t.Run("Valid P2PKH", func(t *testing.T) {
			tx := []byte{42}
			pubKeyHash, pubKey, sig := createSig(t, tx)

			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG", pubKeyHash)).
				WithUnlockScript(fmt.Sprintf("%s %s", sig, pubKey)).
				WithSignedBytes(tx).
				Validate()

			ok := i.Evaluate()
			assert.True(t, ok)
		})

		t.Run("Invalid P2PKH", func(t *testing.T) {
			tx := []byte{42}
			pubKeyHash, pubKey, sig := createSig(t, tx)

			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("OP_DUP OP_HASH160 %s OP_EQUALVERIFY OP_CHECKSIG", pubKeyHash)).
				WithUnlockScript(fmt.Sprintf("%s %s", sig, pubKey)).
				WithSignedBytes([]byte{24}).
				Validate()

			ok := i.Evaluate()
			assert.False(t, ok)
		})

		t.Run("Valid multisig", func(t *testing.T) {
			tx := []byte{42}
			_, pk1, sig1 := createSig(t, tx)
			_, pk2, _ := createSig(t, tx)
			_, pk3, sig3 := createSig(t, tx)

			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("2 %s %s %s 3 OP_CHECKMULTISIG", pk1, pk2, pk3)).
				WithUnlockScript(fmt.Sprintf("%s %s", sig3, sig1)).
				WithSignedBytes(tx).
				Validate()

			ok := i.Evaluate()
			assert.True(t, ok)
		})

		t.Run("Invalid multisig not enough signatures", func(t *testing.T) {
			tx := []byte{42}
			_, pk1, sig1 := createSig(t, tx)
			_, pk2, _ := createSig(t, tx)
			_, pk3, _ := createSig(t, tx)

			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("2 %s %s %s 3 OP_CHECKMULTISIG", pk1, pk2, pk3)).
				WithUnlockScript(fmt.Sprintf("%s", sig1)).
				WithSignedBytes(tx).
				Validate()

			ok := i.Evaluate()
			assert.False(t, ok)
		})

		t.Run("Invalid multisig invalid signature", func(t *testing.T) {
			tx := []byte{42}
			_, pk1, sig1 := createSig(t, tx)
			_, pk2, _ := createSig(t, tx)
			_, pk3, _ := createSig(t, tx)
			_, _, sig4 := createSig(t, tx)

			i, _ := scripts.NewTxInputInterpreter().
				WithLockScript(fmt.Sprintf("2 %s %s %s 3 OP_CHECKMULTISIG", pk1, pk2, pk3)).
				WithUnlockScript(fmt.Sprintf("%s %s", sig1, sig4)).
				WithSignedBytes(tx).
				Validate()

			ok := i.Evaluate()
			assert.False(t, ok)
		})
	})
}
