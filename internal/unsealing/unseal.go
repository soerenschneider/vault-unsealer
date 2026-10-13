package unsealing

import (
	"context"
	"errors"
)

var ErrUnsealPermanent = errors.New("can not retrieve unseal key")

type UnsealKeyRetriever interface {
	RetrieveUnsealKey(ctx context.Context) (string, error)
	Name() string
}

// CachingUnsealKeyRetriever is implemented by retrievers that cache the unseal key.
type CachingUnsealKeyRetriever interface {
	UnsealKeyRetriever
	// Invalidate discards the cached key, so it's retrieved from the source again on the next call.
	Invalidate()
	// Refresh retrieves the key from the source, bypassing the cache. The cached key is only replaced if retrieval
	// succeeds.
	Refresh(ctx context.Context) error
}
