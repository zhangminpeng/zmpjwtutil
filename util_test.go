package zmpjwtutil

import (
	"github.com/kataras/jwt"
	"testing"
	"time"
)

const (
	Key = "987654321"
)

func TestJwtToken(t *testing.T) {

	claim := jwt.Claims{
		ID:       "123456",
		OriginID: "mpzhang",
	}

	token := CreateJwtToken(Key, claim, 5*time.Minute)
	t.Logf("token: %s", token)

	err := VerifyJwtToken(Key, token)
	if err != nil {
		t.Logf("token verify failed: %s", err.Error())
	} else {
		t.Logf("token verify succeed")
	}
}
