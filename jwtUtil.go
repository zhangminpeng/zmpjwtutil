package zmpjwtutil

import (
	"bytes"
	"errors"
	gub "gitee.com/shibingli/goutils/bytes"
	"github.com/golang-module/dongle"
	"github.com/kataras/jwt"
	"strings"
	"time"
	"zmpjwtutil/commons"
)

var (
	MaxAge     = jwt.MaxAge
	ErrExpired = jwt.ErrExpired
	DefaultAlg = jwt.HS256
)

type TokenPair struct {
	AccessToken string `json:"access_token,omitempty"`
}

func NewTokenPair(accessToken []byte, hex ...bool) *TokenPair {
	accessToken = bytes.TrimSpace(accessToken)

	tp := &TokenPair{}
	if IsHex(hex...) {
		tp.AccessToken = dongle.Encode.FromBytes(accessToken).ByHex().ToString()
	} else {
		tp.AccessToken = jwt.BytesToString(accessToken)
	}
	return tp
}

func IsHex(hex ...bool) bool {
	enHex := false

	if commons.HexSwitch {
		enHex = commons.HexSwitch
	}

	if len(hex) > 0 {
		enHex = hex[0]
	}

	return enHex
}

func Decode(token string, hex ...bool) (claims interface{}, err error) {

	if IsHex(hex...) {
		token = DeCodeHexString(token)
	}

	var ut *jwt.UnverifiedToken
	ut, err = jwt.Decode(gub.UnsafeBytes(token))
	if err != nil {
		return
	}

	err = ut.Claims(&claims)
	if err != nil {
		return
	}

	if claims == nil {
		err = jwt.ErrNotValidYet
		return
	}

	return
}

func Sign(key string, claims interface{}, opts ...jwt.SignOption) ([]byte, error) {
	return jwt.Sign(DefaultAlg, gub.UnsafeBytes(key), claims, opts...)
}

func Verify(key, token string, validators ...jwt.TokenValidator) (*jwt.VerifiedToken, error) {
	return jwt.Verify(DefaultAlg, gub.UnsafeBytes(key), gub.UnsafeBytes(token), validators...)
}

func CreateJwtToken(key string, claim interface{}, tokenMaxAge time.Duration, hex ...bool) (accessToken string) {
	var accessTokenBytes []byte
	accessTokenBytes, err := Sign(key, claim, jwt.MaxAge(tokenMaxAge))

	if err != nil {
		return
	}

	if IsHex(hex...) {
		return EnCodeHexByte(accessTokenBytes)
	} else {
		return jwt.BytesToString(accessTokenBytes)
	}
}

func VerifyJwtToken(key, token string, hex ...bool) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("invalid token")
	}
	if IsHex(hex...) {
		token = dongle.Decode.FromString(token).ByHex().ToString()
	}
	_, err := Verify(key, token)
	if err != nil {
		return err
	}

	return nil
}

func DeCodeHexString(str string) string {
	return dongle.Decode.FromString(str).ByHex().ToString()
}

func EnCodeHexByte(b []byte) string {
	return dongle.Encode.FromBytes(b).ByHex().ToString()
}
