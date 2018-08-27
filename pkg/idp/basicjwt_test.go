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
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	m := make(map[string]interface{})
	m["instance_id"] = "i-test1"
	idp := NewBasicJWTIdentityProvider("sts", nil)
	token, actual := idp.Token("lucas", 10*time.Second, m)
	var expected error = nil
	if actual != expected {
		t.Errorf("Expected the result to be %v but instead got %v", expected, actual)
	}
	t.Log(token)
}

func TestValidate(t *testing.T) {
	m := make(map[string]interface{})
	m["instance_id"] = "i-test1"
	idp := NewBasicJWTIdentityProvider("sts", nil)
	token, _ := idp.Token("token", 10*time.Second, m)
	idp2 := NewBasicJWTIdentityProvider("sts", nil)
	claims, err := idp2.Validate(token)
	if err != nil {
		t.Errorf("Got err: %s", err)
		return
	}
	var actual = claims["sub"].(string)
	var expected = "token"
	if actual != expected {
		t.Errorf("Expected the result to be %s but instead got %s", expected, actual)
	}
	t.Logf("%v", claims)
}
