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

package service

import (
	"context"
	"fmt"
	"sts/pkg/client"
)

type Service interface {
	AssumeRole(ctx context.Context, role string) (string, error)
}

type sts struct{}

func NewSts() Service {
	return &sts{}
}

func (s sts) AssumeRole(ctx context.Context, role string) (string, error) {
	// Firstly we check the resource-based-policy for the role if it could be assumed
	err := client.Evaluation(ctx, role)
	if err != nil {
		return "", err
	}

	//todo: attempt to get an id token from issuer

	fmt.Println("evaluation was allowed")

	return "", nil
}
