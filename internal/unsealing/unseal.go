package unsealing

import (
	"context"
	"errors"
)

var UnsealPermanentError = errors.New("can not retrieve unseal key")

type UnsealKeyRetriever interface {
	RetrieveUnsealKey(ctx context.Context) (string, error)
}
