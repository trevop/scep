package challenge

import (
	"context"
	"errors"
)

type Service interface {
	SCEPChallenge(ctx context.Context) (string, error)
}

type ChallengeService struct {
	Store
}

func (c *ChallengeService) SCEPChallenge(_ context.Context) (string, error) {
	if c.Store == nil {
		return "", errors.New("SCEP challenge store missing")
	}
	return c.Store.SCEPChallenge()
}

func NewService(challengeStore Store) *ChallengeService {
	return &ChallengeService{
		Store: challengeStore,
	}
}
