package svid

import (
	"testing"
	"time"

	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRotator(t *testing.T) {
	// Case 1: Defaults
	r1, _ := NewRotator(&RotatorConfig{})
	require.NotNil(t, r1)
	rot1, ok := r1.(*rotator)
	require.True(t, ok, "expected *rotator type")
	assert.Equal(t, DefaultRotatorInterval, rot1.c.Interval)
	assert.NotNil(t, rot1.clk)

	// Case 2: Custom values
	customInterval := 10 * time.Second
	mockClock := clock.NewMock(t)
	r2, _ := NewRotator(&RotatorConfig{
		Interval: customInterval,
		Clk:      mockClock,
	})
	require.NotNil(t, r2)
	rot2, ok := r2.(*rotator)
	require.True(t, ok, "expected *rotator type")
	assert.Equal(t, customInterval, rot2.c.Interval)
	assert.Equal(t, mockClock, rot2.clk)
}
