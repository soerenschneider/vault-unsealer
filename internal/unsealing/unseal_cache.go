package unsealing

import (
	"context"
	"errors"
	"github.com/rs/zerolog/log"
	"sync"
)

type CachedUnsealKeyRetriever struct {
	retriever UnsealKeyRetriever
	unsealKey *string
	mutex     sync.Mutex
}

func NewCachedUnsealKeyRetriever(retriever UnsealKeyRetriever) (*CachedUnsealKeyRetriever, error) {
	if retriever == nil {
		return nil, errors.New("empty impl provided")
	}

	return &CachedUnsealKeyRetriever{
		retriever: retriever,
		mutex:     sync.Mutex{},
	}, nil
}

func (r *CachedUnsealKeyRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	if r.unsealKey == nil {
		log.Info().Msg("Trying to cache unseal key")
		r.mutex.Lock()
		defer r.mutex.Unlock()
		if r.unsealKey == nil {
			unsealKey, err := r.retriever.RetrieveUnsealKey(ctx)
			if err != nil {
				return "", err
			}
			r.unsealKey = &unsealKey
		}
	}

	return *r.unsealKey, nil
}
