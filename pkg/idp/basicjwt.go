/*
 * Copyright (c) 2018. LuCongyao <6congyao@gmail.com> .
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this work except in compliance with the License.
 * You may obtain a copy of the License in the LICENSE file, or at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package idp

import (
	"crypto/rsa"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"sts/utils/nuid"
	"time"
)

const (
	issuer      = "sts"
	idTokenType = "ID"
	party       = "iam"
	notBefore   = 0
	acr         = "1"
)

var (
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")
)

type BasicJWTIdentityProvider struct {
	secret []byte
	rsapk  *rsa.PrivateKey
}

func NewBasicJWTIdentityProvider(secret string, key *rsa.PrivateKey) IdentityProvider {
	return &BasicJWTIdentityProvider{[]byte(secret), key}
}

func (idp *BasicJWTIdentityProvider) Token(id string, d time.Duration, m map[string]interface{}) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(d)

	m["sub"] = id
	m["iss"] = issuer
	m["nbf"] = notBefore
	m["aud"] = party
	m["azp"] = party
	m["typ"] = idTokenType
	m["acr"] = acr
	m["iat"] = now.Unix()
	m["exp"] = exp.Unix()
	m["jti"] = nuid.Next()

	if idp.rsapk != nil {
		return idp.rsaGen(m)
	}

	return idp.hsaGen(m)
}

func (idp *BasicJWTIdentityProvider) hsaGen(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(idp.secret)
}

func (idp *BasicJWTIdentityProvider) rsaGen(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(idp.rsapk)
}

func (idp *BasicJWTIdentityProvider) Validate(tokenStr string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnauthorizedAccess
		}
		return idp.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrUnauthorizedAccess
}

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}
