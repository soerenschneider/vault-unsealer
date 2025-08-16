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
