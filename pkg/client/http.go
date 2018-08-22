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

package client

import (
	"context"
	"os"
	"sts/utils/pester"
	"net/url"
	"net/http"
	"strings"
	"io/ioutil"
	"github.com/pkg/errors"
	"bytes"
	"fmt"
	"io"
	"encoding/json"
	"sts/utils/logger"
)

const (
	EnvEvaURL    = "STS_EVA_URL"
	EnvIssuerURL = "STS_ISSUER_URL"
	EnvIssuerClientId = "STS_ISSUER_CLIENT_ID"
	EnvIssuerClientSecret = "STS_ISSUER_CLIENT_SECRET"
)

var pst *pester.Client
var evaurl string
var issuerUrl string
var issuerCilentId string
var issuerClientSecret string
var defaultPayload = &[]map[string]interface{}{
	{"action": "sts:AssumeRole", "principal": "ec2.qingcloud.com"},
}

func init() {
	pst = pester.New()
	pst.MaxRetries = 3
	pst.KeepLog = true

	evaurl = os.Getenv(EnvEvaURL)
	issuerUrl = os.Getenv(EnvIssuerURL)
	issuerCilentId = os.Getenv(EnvIssuerClientId)
	issuerClientSecret = os.Getenv(EnvIssuerClientSecret)
}

func Evaluate(ctx context.Context, role, principal string) error {
	//ctx, cancel := context.WithCancel(ctx)
	//defer cancel()
	var payload *[]map[string]interface{}
	if principal == "" {
		payload = defaultPayload
	} else {
		payload = &[]map[string]interface{}{
			{"action": "sts:AssumeRole", "principal": principal},
		}
	}

	evaRequestContext := map[string]interface{}{
		"payload": payload,
	}

	evaRequestContext["subject"] = role

	byteRequest, err := json.Marshal(evaRequestContext)
	if err != nil {
		return err
	}

	res, err := pst.Post(evaurl, "application/json", bytes.NewReader(byteRequest))

	if err != nil {
		logger.Error.Printf("evaluation error: %s", pst.LogString())
		return err
	}
	defer res.Body.Close()
	io.Copy(ioutil.Discard, res.Body)

	if res.StatusCode != http.StatusOK {
		logger.Debug.Printf("Evaluate was denied, request contest: %s", string(byteRequest))
		return errors.New(fmt.Sprintf("evaluation was denied. [%d]", res.StatusCode))
	}

	return nil
}

func Issue(ctx context.Context, instanceProfile map[string]string) (string, error) {

	data := url.Values{}
	data.Add("grant_type", "client_credentials")
	data.Add("client_id", issuerCilentId)
	data.Add("client_secret", issuerClientSecret)
	data.Add("scope", "openid")

	var r http.Request

	r.ParseForm()
	r.Form = data

	req, err1 := http.NewRequest(http.MethodPost, issuerUrl, strings.NewReader(r.Form.Encode()))
	if err1 != nil {
		return "", err1
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range instanceProfile {
		req.Header.Set(k, v)
	}

	res, err2 := pst.Do(req)
	if err2 != nil {
		return "", err2
	}
	defer res.Body.Close()
	//io.Copy(ioutil.Discard, res.Body)

	if res.StatusCode != http.StatusOK {
		return "", errors.New("issuer is invalid")
	}
	bodyBytes, err2 := ioutil.ReadAll(res.Body)
	token := string(bodyBytes)

	return token, nil
}
