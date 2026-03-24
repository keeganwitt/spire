package catalog_test

import (
	"fmt"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/assert"
)

func TestConstraints(t *testing.T) {
	testCases := []struct {
		name        string
		constraints catalog.Constraints
		count       int
		expectedErr string
	}{
		// ExactlyOne
		{name: "ExactlyOne (0)", constraints: catalog.ExactlyOne(), count: 0, expectedErr: "expected exactly 1 but got 0"},
		{name: "ExactlyOne (1)", constraints: catalog.ExactlyOne(), count: 1},
		{name: "ExactlyOne (2)", constraints: catalog.ExactlyOne(), count: 2, expectedErr: "expected exactly 1 but got 2"},

		// MaybeOne
		{name: "MaybeOne (0)", constraints: catalog.MaybeOne(), count: 0},
		{name: "MaybeOne (1)", constraints: catalog.MaybeOne(), count: 1},
		{name: "MaybeOne (2)", constraints: catalog.MaybeOne(), count: 2, expectedErr: "expected at most 1 but got 2"},

		// AtLeastOne
		{name: "AtLeastOne (0)", constraints: catalog.AtLeastOne(), count: 0, expectedErr: "expected at least 1 but got 0"},
		{name: "AtLeastOne (1)", constraints: catalog.AtLeastOne(), count: 1},
		{name: "AtLeastOne (2)", constraints: catalog.AtLeastOne(), count: 2},

		// ZeroOrMore
		{name: "ZeroOrMore (0)", constraints: catalog.ZeroOrMore(), count: 0},
		{name: "ZeroOrMore (1)", constraints: catalog.ZeroOrMore(), count: 1},
		{name: "ZeroOrMore (10)", constraints: catalog.ZeroOrMore(), count: 10},

		// Custom Range (2-5)
		{name: "Range 2-5 (1)", constraints: catalog.Constraints{Min: 2, Max: 5}, count: 1, expectedErr: "expected at least 2 but got 1"},
		{name: "Range 2-5 (2)", constraints: catalog.Constraints{Min: 2, Max: 5}, count: 2},
		{name: "Range 2-5 (3)", constraints: catalog.Constraints{Min: 2, Max: 5}, count: 3},
		{name: "Range 2-5 (5)", constraints: catalog.Constraints{Min: 2, Max: 5}, count: 5},
		{name: "Range 2-5 (6)", constraints: catalog.Constraints{Min: 2, Max: 5}, count: 6, expectedErr: "expected at most 5 but got 6"},

		// Custom Exact (3-3)
		{name: "Exact 3 (2)", constraints: catalog.Constraints{Min: 3, Max: 3}, count: 2, expectedErr: "expected exactly 3 but got 2"},
		{name: "Exact 3 (3)", constraints: catalog.Constraints{Min: 3, Max: 3}, count: 3},
		{name: "Exact 3 (4)", constraints: catalog.Constraints{Min: 3, Max: 3}, count: 4, expectedErr: "expected exactly 3 but got 4"},

		// Custom At Least 2 (2-0)
		{name: "At Least 2 (1)", constraints: catalog.Constraints{Min: 2, Max: 0}, count: 1, expectedErr: "expected at least 2 but got 1"},
		{name: "At Least 2 (2)", constraints: catalog.Constraints{Min: 2, Max: 0}, count: 2},
		{name: "At Least 2 (3)", constraints: catalog.Constraints{Min: 2, Max: 0}, count: 3},

		// Custom At Most 2 (0-2)
		{name: "At Most 2 (0)", constraints: catalog.Constraints{Min: 0, Max: 2}, count: 0},
		{name: "At Most 2 (1)", constraints: catalog.Constraints{Min: 0, Max: 2}, count: 1},
		{name: "At Most 2 (2)", constraints: catalog.Constraints{Min: 0, Max: 2}, count: 2},
		{name: "At Most 2 (3)", constraints: catalog.Constraints{Min: 0, Max: 2}, count: 3, expectedErr: "expected at most 2 but got 3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.constraints.Check(tc.count)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func ExampleConstraints_Check() {
	c := catalog.Constraints{Min: 1, Max: 2}
	fmt.Println(c.Check(0))
	fmt.Println(c.Check(1))
	fmt.Println(c.Check(2))
	fmt.Println(c.Check(3))
	// Output:
	// expected at least 1 but got 0
	// <nil>
	// <nil>
	// expected at most 2 but got 3
}
