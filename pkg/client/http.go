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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sts/utils/pester"
)

const (
	EnvEvaURL    = "STS_EVA_URL"
	EnvIssuerURL = "STS_ISSUER_URL"
)

var pst *pester.Client
var evaurl string
var issuerurl string
var payload = &[]map[string]interface{}{
	{"action": "sts:AssumeRole", "principal": "ec2.qingcloud.com"},
}

func init() {
	pst = pester.New()
	pst.MaxRetries = 3
	pst.KeepLog = true

	evaurl = os.Getenv(EnvEvaURL)
	issuerurl = os.Getenv(EnvIssuerURL)
}

func Evaluate(ctx context.Context, role string) error {
	//ctx, cancel := context.WithCancel(ctx)
	//defer cancel()

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
		fmt.Println("evaluation error:", pst.LogString())
		return err
	}
	defer res.Body.Close()
	io.Copy(ioutil.Discard, res.Body)

	if res.StatusCode != http.StatusOK {
		return errors.New("evaluation was denied")
	}

	return nil
}

func Issue(ctx context.Context) error {
	//todo: ask issuer instance for id token
	return nil
}