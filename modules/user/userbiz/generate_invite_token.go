package userbiz

import (
	"app-invite-service/common"
	"app-invite-service/modules/user/usermodel"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"time"
)

// Adapted from https://elithrar.github.io/article/generating-secure-random-numbers-crypto-rand/
func init() {
	assertAvailablePRNG()
}

func assertAvailablePRNG() {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)
	_, err := io.ReadFull(crand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(min, max int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(max-min) + min
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := crand.Int(crand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret), nil
}

type GenerateTokenStore interface {
	// FindUser(ctx context.Context, conditions map[string]interface{}, moreInfo ...string) (*usermodel.User, error)
}

type generateTokenBiz struct {
	generateTokenStore GenerateTokenStore
}

func NewGenerateTokenBiz(generateTokenStore GenerateTokenStore) *generateTokenBiz {
	return &generateTokenBiz{generateTokenStore: generateTokenStore}
}

func (biz *generateTokenBiz) GenerateToken(ctx context.Context) (*usermodel.InviteToken, error) {
	var minTokenLen = 6
	var maxTokenLen = 12
	token, err := GenerateRandomString(minTokenLen, maxTokenLen)
	if err != nil {
		return nil, err
	}

	val, err := biz.generateTokenStore.SetNX(ctx, token, token, common.InviteTokenExpirySecond*time.Second).Result()
	if err != nil {
		return nil, err
	}

	return &usermodel.InviteToken{Token: token}, nil
}
