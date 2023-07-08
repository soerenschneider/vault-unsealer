package unsealing

import (
	"context"
	"errors"
)

// StaticUnsealKeyRetriever is the simplest way to retrieve an unseal key but also the most insecure. It should
// *really* only be used to test things.
type StaticUnsealKeyRetriever struct {
	unsealKey string
}

func NewStaticUnsealKeyRetriever(unsealKey string) (*StaticUnsealKeyRetriever, error) {
	if len(unsealKey) == 0 {
		return nil, errors.New("empty unseal key provided")
	}

	return &StaticUnsealKeyRetriever{
		unsealKey: unsealKey,
	}, nil
}

func (r *StaticUnsealKeyRetriever) RetrieveUnsealKey(_ context.Context) (string, error) {
	return r.unsealKey, nil
}
