package unsealing

import "context"

// StaticUnsealKeyRetriever is the simplest way to retrieve an unseal key but also the most insecure. It should
// *really* only be used to test things.
type StaticUnsealKeyRetriever struct {
	unsealKey string
}

func NewStaticUnsealKeyRetriever(unsealKey string) (*StaticUnsealKeyRetriever, error) {
	return &StaticUnsealKeyRetriever{
		unsealKey: unsealKey,
	}, nil
}

func (r *StaticUnsealKeyRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	return r.unsealKey, nil
}
