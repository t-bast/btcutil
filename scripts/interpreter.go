package scripts

import "strings"

// Interpreter for a Bitcoin script.
type Interpreter interface {
	// Evaluate the script.
	Evaluate() bool
}

// TxInputInterpreter interprets a transaction's unlock script.
type TxInputInterpreter struct {
	signedBytes  []byte
	lockScript   []string
	unlockScript []string
}

// NewTxInputInterpreter creates an interpreter for a transaction input.
// You will need to set
func NewTxInputInterpreter() *TxInputInterpreter {
	return &TxInputInterpreter{}
}

// WithLockScript sets the locking script (pubKeyScript).
func (i *TxInputInterpreter) WithLockScript(lockScript string) *TxInputInterpreter {
	i.lockScript = strings.Split(lockScript, " ")
	return i
}

// WithUnlockScript sets the unlocking script (sigScript).
func (i *TxInputInterpreter) WithUnlockScript(unlockScript string) *TxInputInterpreter {
	i.unlockScript = strings.Split(unlockScript, " ")
	return i
}

// WithSignedBytes sets the bytes that should be used for signature
// verification.
func (i *TxInputInterpreter) WithSignedBytes(b []byte) *TxInputInterpreter {
	i.signedBytes = make([]byte, len(b))
	copy(i.signedBytes, b)
	return i
}

// Validate the script (without evaluating it).
// You can use the returned Interpreter to actually evaluate the script.
func (i *TxInputInterpreter) Validate() (Interpreter, error) {
	// TODO: add some script validation.
	return i, nil
}

// Evaluate the script.
func (i *TxInputInterpreter) Evaluate() bool {
	stack := InitStack().WithTxBytes(i.signedBytes)
	ok := stack.ExecuteUnlock(i.unlockScript)
	if !ok {
		return false
	}

	return stack.Execute(i.lockScript)
}
