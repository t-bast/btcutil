package scripts_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/btcutil/scripts"
)

func TestStack(t *testing.T) {
	type testCase struct {
		name     string
		script   []string
		state    []string
		expected bool
	}

	t.Run("Execute()", func(t *testing.T) {
		testCases := []testCase{
			{
				"dangling operator",
				[]string{
					"suchValue",
					"OP_ADD",
				},
				[]string{
					"suchValue",
				},
				false,
			}, {
				"empty stack",
				[]string{
					"veryPubKey",
					"OP_DROP",
				},
				nil,
				false,
			}, {
				"too many stack results",
				[]string{
					"1",
					"2",
					"OP_ADD",
					"OP_DUP",
				},
				[]string{
					"3",
					"3",
				},
				false,
			}, {
				"unsatisfied equal",
				[]string{
					"1",
					"2",
					"OP_EQUAL",
				},
				[]string{
					"0",
				},
				false,
			}, {
				"unsatisfied verify",
				[]string{
					"1",
					"2",
					"OP_EQUALVERIFY",
					"OP_DROP",
					"OP_TRUE",
				},
				nil,
				false,
			}, {
				"satisfied equal",
				[]string{
					"2",
					"2",
					"OP_EQUAL",
				},
				[]string{
					"1",
				},
				true,
			}}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				s := scripts.InitStack()
				assert.Equal(t, tt.expected, s.Execute(tt.script))
				assert.Equal(t, tt.state, s.Print())
			})
		}
	})

	t.Run("ExecuteUnlock()", func(t *testing.T) {
		testCases := []testCase{
			{
				"dangling operator",
				[]string{
					"suchValue",
					"OP_ADD",
				},
				[]string{
					"suchValue",
				},
				false,
			},
			{
				"empty stack",
				[]string{
					"veryPubKey",
					"OP_DROP",
				},
				nil,
				false,
			},
			{
				"unsatisfied verify",
				[]string{
					"1",
					"2",
					"OP_EQUALVERIFY",
				},
				nil,
				false,
			},
			{
				"return false",
				[]string{
					"1",
					"2",
					"OP_EQUAL",
				},
				[]string{
					"0",
				},
				true,
			},
			{
				"multiple values",
				[]string{
					"muchSig",
					"veryPubKey",
				},
				[]string{
					"muchSig",
					"veryPubKey",
				},
				true,
			},
		}

		for _, tt := range testCases {
			t.Run(tt.name, func(t *testing.T) {
				s := scripts.InitStack()
				assert.Equal(t, tt.expected, s.ExecuteUnlock(tt.script))
				assert.Equal(t, tt.state, s.Print())
			})
		}
	})
}
