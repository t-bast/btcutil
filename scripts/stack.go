package scripts

import (
	"errors"
	"fmt"
	"strconv"
)

// Stack is the execution stack of a Bitcoin script.
type Stack struct {
	values []string
}

// Operation applies transformations to the stack.
// If it returns an error the execution should be halted.
type Operation func(*Stack) error

// InitStack initializes an empty stack.
func InitStack() *Stack {
	return &Stack{}
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
				return err
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
	"OP_TRUE": func(s *Stack) error {
		s.Push("1")
		return nil
	},
	"OP_FALSE": func(s *Stack) error {
		s.Push("0")
		return nil
	},
	"OP_DUP": func(s *Stack) error {
		if s.Size() == 0 {
			return nil
		}

		v := s.Pop()
		s.Push(v)
		s.Push(v)

		return nil
	},
	"OP_ADD": func(s *Stack) error {
		if s.Size() < 2 {
			return errors.New("OP_ADD requires two values on the stack")
		}

		v1, err := s.PopInt()
		if err != nil {
			return err
		}

		v2, err := s.PopInt()
		if err != nil {
			return err
		}

		s.Push(strconv.FormatInt(v1+v2, 10))

		return nil
	},
	"OP_DROP": func(s *Stack) error {
		if s.Size() > 0 {
			s.Pop()
		}

		return nil
	},
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
			s.Push("0")
			return errors.New("evaluated to false")
		}

		s.Push("1")
		return nil
	},
}
