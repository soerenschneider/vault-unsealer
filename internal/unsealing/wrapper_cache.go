package unsealing

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

type CachedUnsealKeyRetriever struct {
	retriever UnsealKeyRetriever
	unsealKey *string
	mutex     sync.RWMutex
}

func NewCachedUnsealKeyRetriever(retriever UnsealKeyRetriever) (*CachedUnsealKeyRetriever, error) {
	if retriever == nil {
		return nil, errors.New("empty impl provided")
	}

	return &CachedUnsealKeyRetriever{
		retriever: retriever,
		mutex:     sync.RWMutex{},
	}, nil
}

func (r *CachedUnsealKeyRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	r.mutex.RLock()
	if r.unsealKey != nil {
		key := *r.unsealKey
		r.mutex.RUnlock()
		return key, nil
	}
	r.mutex.RUnlock()

	log.Info().Msg("Trying to cache unseal key")

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Double-check after acquiring the write lock.
	if r.unsealKey == nil {
		unsealKey, err := r.retriever.RetrieveUnsealKey(ctx)
		if err != nil {
			return "", err
		}
		r.unsealKey = &unsealKey
	}

	return *r.unsealKey, nil
}

func (r *CachedUnsealKeyRetriever) Refresh(ctx context.Context) error {
	unsealKey, err := r.retriever.RetrieveUnsealKey(ctx)
	if err != nil {
		return err
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.unsealKey = &unsealKey
	return nil
}

func (r *CachedUnsealKeyRetriever) Invalidate() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.unsealKey = nil
}

func (r *CachedUnsealKeyRetriever) Name() string {
	return fmt.Sprintf("cached-%s", r.retriever.Name())
}
