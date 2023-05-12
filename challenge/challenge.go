// Package challenge defines an interface for a dynamic challenge password cache.
package challenge

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/go-kit/kit/endpoint"

	"github.com/micromdm/scep/v2/scep"
	scepserver "github.com/micromdm/scep/v2/server"
)

// Store is a dynamic challenge password cache.
type Store interface {
	SCEPChallenge() (string, error)
	HasChallenge(pw string) (bool, error)
}

// Middleware wraps next in a CSRSigner that verifies and invalidates the challenge
func Middleware(store Store, next scepserver.CSRSigner) scepserver.CSRSignerFunc {
	return func(m *scep.CSRReqMessage) (*x509.Certificate, error) {
		// TODO: compare challenge only for PKCSReq?
		valid, err := store.HasChallenge(m.ChallengePassword)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, errors.New("invalid challenge")
		}
		return next.SignCSR(m)
	}
}

type challengeResponse struct {
	Challenge string `json:"string"`
	Err       error  `json:"err,omitempty"`
}

func (r challengeResponse) Failed() error { return r.Err }

func MakeChallengeEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		r := challengeResponse{}
		r.Challenge, r.Err = svc.SCEPChallenge(ctx)
		return r, nil
	}
}
