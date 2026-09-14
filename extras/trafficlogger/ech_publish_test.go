package trafficlogger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECHPublishStatus(t *testing.T) {
	s := NewECHPublishStatus([]string{"a.example.com", "b.example.com"})
	assert.Equal(t, ECHPublishPending, s.State())

	// One done, one still pending: the whole is pending.
	s.Published("a.example.com")
	assert.Equal(t, ECHPublishPending, s.State())

	s.Published("b.example.com")
	assert.Equal(t, ECHPublishPublished, s.State())

	// Any failure wins over everything else.
	s.Failed("b.example.com")
	assert.Equal(t, ECHPublishFailed, s.State())

	// No domains at all cannot happen (validation rejects it), but the fold
	// still gives a sane answer rather than a stray pending.
	assert.Equal(t, ECHPublishPublished, NewECHPublishStatus(nil).State())

	// A domain that was never registered is a bug, not a new entry.
	assert.Panics(t, func() { s.Published("c.example.com") })
}
