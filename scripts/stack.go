package scripts

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"

	"golang.org/x/crypto/ripemd160"
)

// Stack is the execution stack of a Bitcoin script.
type Stack struct {
	tx     []byte
	values []string
}

// Operation applies transformations to the stack.
// If it returns an error the execution should be halted.
type Operation func(*Stack) error

// InitStack initializes an empty stack.
func InitStack() *Stack {
	return &Stack{}
}

// WithTxBytes sets the transaction bytes for signature verification.
func (s *Stack) WithTxBytes(b []byte) *Stack {
	s.tx = make([]byte, len(b))
	copy(s.tx, b)
	return s
}

// Pop one value from the stack.
func (s *Stack) Pop() string {
	n := len(s.values)
	v := s.values[n-1]
	s.values = s.values[:n-1]
	return v
}

// PopInt pops an integer value from the stack.
func (s *Stack) PopInt() (int64, error) {
	v := s.Pop()
	return strconv.ParseInt(v, 0, 0)
}

// Push a value on the stack.
func (s *Stack) Push(val string) {
	s.values = append(s.values, val)
}

// Size of the stack.
func (s *Stack) Size() int {
	return len(s.values)
}

// Print the stack.
func (s *Stack) Print() []string {
	if len(s.values) == 0 {
		return nil
	}

	res := make([]string, len(s.values))
	copy(res, s.values)
	return res
}

func (s *Stack) execute(script []string) error {
	for _, val := range script {
		if isOpCode(val) {
			op, ok := ops[val]
			if !ok {
				return fmt.Errorf("unsupported opcode: %s", val)
			}

			if err := op(s); err != nil {
				return errors.Wrap(err, "operation failed")
			}
		} else {
			s.values = append(s.values, val)
		}
	}

	return nil
}

// Execute the given script and returns the outcome.
func (s *Stack) Execute(script []string) bool {
	if err := s.execute(script); err != nil {
		return false
	}

	if len(s.values) != 1 {
		return false
	}

	if s.values[0] == "0" {
		return false
	}

	return true
}

// ExecuteUnlock executes an unlock script and returns the outcome.
func (s *Stack) ExecuteUnlock(script []string) bool {
	if err := s.execute(script); err != nil {
		return false
	}

	// If the stack contains operators, this is considered invalid.
	for _, sval := range s.values {
		if isOpCode(sval) {
			return false
		}
	}

	if len(s.values) == 0 {
		return false
	}

	return true
}

func isOpCode(val string) bool {
	return len(val) > 3 && val[:3] == "OP_"
}

// Apply the given opcode.
var ops = map[string]Operation{
	// Pushing values to the stack.
	"OP_TRUE": func(s *Stack) error {
		s.Push("1")
		return nil
	},
	"OP_FALSE": func(s *Stack) error {
		s.Push("0")
		return nil
	},

	// Conditional statements.
	"OP_VERIFY": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_EQUALVERIFY requires a value on the stack")
		}

		v := s.Pop()

		if v != "1" {
			return errors.New("evaluated to false")
		}

		return nil
	},
	"OP_RETURN": func(s *Stack) error {
		return errors.New("OP_RETURN halts execution")
	},

	// Stack operations.
	"OP_DUP": func(s *Stack) error {
		if s.Size() == 0 {
			return nil
		}

		v := s.Pop()
		s.Push(v)
		s.Push(v)

		return nil
	},
	"OP_DROP": func(s *Stack) error {
		if s.Size() > 0 {
			s.Pop()
		}

		return nil
	},

	// Binary arithmetic and conditionals.
	"OP_EQUAL": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_EQUAL requires two values on the stack")
		}

		v1 := s.Pop()
		v2 := s.Pop()

		if v1 == v2 {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return nil
	},
	"OP_EQUALVERIFY": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_EQUALVERIFY requires two values on the stack")
		}

		v1 := s.Pop()
		v2 := s.Pop()

		if v1 != v2 {
			return errors.New("evaluated to false")
		}

		return nil
	},

	// Numeric operators.
	"OP_ADD": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_ADD requires two values on the stack")
		}

		v1, err := s.PopInt()
		if err != nil {
			return errors.Wrap(err, "stack value isn't a number")
		}

		v2, err := s.PopInt()
		if err != nil {
			return errors.Wrap(err, "stack value isn't a number")
		}

		s.Push(strconv.FormatInt(v1+v2, 10))

		return nil
	},
	"OP_NOT": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_NOT requires a value on the stack")
		}

		v := s.Pop()
		if v == "0" {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return nil
	},
	"OP_SUB": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_SUB requires two values on the stack")
		}

		v1, err := s.PopInt()
		if err != nil {
			return errors.Wrap(err, "stack value isn't a number")
		}

		v2, err := s.PopInt()
		if err != nil {
			return errors.Wrap(err, "stack value isn't a number")
		}

		s.Push(strconv.FormatInt(v2-v1, 10))

		return nil
	},
	"OP_BOOLAND": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_BOOLAND requires two values on the stack")
		}

		b1 := s.Pop()
		b2 := s.Pop()

		if b1 == "1" && b2 == "1" {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return nil
	},
	"OP_BOOLOR": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_BOOLOR requires two values on the stack")
		}

		b1 := s.Pop()
		b2 := s.Pop()

		if b1 == "1" || b2 == "1" {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return nil
	},

	// Cryptographic operations.
	"OP_RIPEMD160": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_RIPEMD160 requires a value on the stack")
		}

		v, err := hex.DecodeString(s.Pop())
		if err != nil {
			return errors.Wrap(err, "stack value should be a hex string")
		}

		vv := hex.EncodeToString(ripemd160.New().Sum(v))
		s.Push(vv)

		return nil
	},
	"OP_SHA1": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_SHA1 requires a value on the stack")
		}

		v, err := hex.DecodeString(s.Pop())
		if err != nil {
			return errors.Wrap(err, "stack value should be a hex string")
		}

		vv := sha1.Sum(v)
		s.Push(hex.EncodeToString(vv[:]))

		return nil
	},
	"OP_SHA256": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_SHA256 requires a value on the stack")
		}

		v, err := hex.DecodeString(s.Pop())
		if err != nil {
			return errors.Wrap(err, "stack value should be a hex string")
		}

		vv := sha256.Sum256(v)
		s.Push(hex.EncodeToString(vv[:]))

		return nil
	},
	"OP_HASH160": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_HASH160 requires a value on the stack")
		}

		v, err := hex.DecodeString(s.Pop())
		if err != nil {
			return errors.Wrap(err, "stack value should be a hex string")
		}

		h1 := sha256.Sum256(v)
		h2 := ripemd160.New().Sum(h1[:])
		s.Push(hex.EncodeToString(h2))

		return nil
	},
	"OP_HASH256": func(s *Stack) error {
		if s.Size() < 1 {
			return errors.New("OP_HASH256 requires a value on the stack")
		}

		v, err := hex.DecodeString(s.Pop())
		if err != nil {
			return errors.Wrap(err, "stack value should be a hex string")
		}

		h1 := sha256.Sum256(v)
		h2 := sha256.Sum256(h1[:])
		s.Push(hex.EncodeToString(h2[:]))

		return nil
	},
	"OP_CHECKSIG": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_CHECKSIG requires two values on the stack")
		}

		ok, err := checkSig(s)
		if ok {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return err
	},
	"OP_CHECKSIGVERIFY": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_CHECKSIGVERIFY requires two values on the stack")
		}

		ok, err := checkSig(s)
		if !ok {
			return errors.New("invalid signature")
		}

		return err
	},
	"OP_CHECKMULTISIG": func(s *Stack) error {
		ok, err := checkMultiSig(s)
		if ok {
			s.Push("1")
		} else {
			s.Push("0")
		}

		return err
	},
	"OP_CHECKMULTISIGVERIFY": func(s *Stack) error {
		ok, err := checkMultiSig(s)
		if !ok {
			return errors.New("invalid signature")
		}

		return err
	},
}

func checkSig(s *Stack) (bool, error) {
	pkBytes, err := hex.DecodeString(s.Pop())
	if err != nil {
		return false, errors.Wrap(err, "public key should be a hex string")
	}

	pubKey, err := btcec.ParsePubKey(pkBytes, btcec.S256())
	if err != nil {
		return false, errors.Wrap(err, "could not parse public key")
	}

	sigBytes, err := hex.DecodeString(s.Pop())
	if err != nil {
		return false, errors.Wrap(err, "signature should be a hex string")
	}

	sig, err := btcec.ParseSignature(sigBytes, btcec.S256())
	if err != nil {
		return false, errors.Wrap(err, "could not parse signature")
	}

	return sig.Verify(s.tx, pubKey), nil
}

func checkMultiSig(s *Stack) (bool, error) {
	// The original implementation has a bug and pops one more element than
	// needed.
	// I'm choosing not to implement compatibility with that bug since this is
	// only meant to be a learning experiment.
	if s.Size() < 1 {
		return false, errors.New("OP_CHECKMULTISIG requires a value for N on the stack")
	}

	n, err := s.PopInt()
	if err != nil {
		return false, errors.Wrap(err, "could not parse value of N")
	}

	if s.Size() < int(n) {
		return false, fmt.Errorf("OP_CHECKMULTISIG needs %d public keys", n)
	}

	pubKeys := make([]*btcec.PublicKey, n)
	for i := 0; i < int(n); i++ {
		pkBytes, err := hex.DecodeString(s.Pop())
		if err != nil {
			return false, errors.Wrap(err, "public key should be a hex string")
		}

		pubKeys[i], err = btcec.ParsePubKey(pkBytes, btcec.S256())
		if err != nil {
			return false, errors.Wrap(err, "could not parse public key")
		}
	}

	if s.Size() < 1 {
		return false, errors.New("OP_CHECKMULTISIG requires a value for M on the stack")
	}

	m, err := s.PopInt()
	if err != nil {
		return false, errors.Wrap(err, "could not parse value of M")
	}

	if s.Size() < int(m) {
		return false, fmt.Errorf("OP_CHECKMULTISIG needs %d signatures", m)
	}

	sigs := make([]*btcec.Signature, m)
	for i := 0; i < int(m); i++ {
		sigBytes, err := hex.DecodeString(s.Pop())
		if err != nil {
			return false, errors.Wrap(err, "signature should be a hex string")
		}

		sigs[i], err = btcec.ParseSignature(sigBytes, btcec.S256())
		if err != nil {
			return false, errors.Wrap(err, "could not parse signature")
		}
	}

	// Very naive, can be optimized.
	for _, sig := range sigs {
		valid := false

		for _, pubKey := range pubKeys {
			valid = sig.Verify(s.tx, pubKey)
			if valid {
				break
			}
		}

		if !valid {
			return false, nil
		}
	}

	return true, nil
}
