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

package main

import (
	"github.com/go-kit/kit/log"
	"os"

	"fmt"
	"net/http"
	"os/signal"
	"strings"
	"sts/pkg/endpoint"
	"sts/pkg/service"
	"sts/pkg/transport"
	"syscall"
)

const (
	EnvPort = "STS_PORT"
)

func main() {
	ec := make(chan error)
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestamp)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	var (
		service     = service.NewSts()
		endpoints   = endpoint.MakeStsEndpoints(service, logger)
		httpHandler = transport.NewHttpHandler(endpoints, logger)
	)

	go func() {
		port := os.Getenv(EnvPort)

		if port == "" {
			port = ":9021"
		} else {
			if !strings.HasPrefix(port, ":") {
				port = ":" + port
			}
		}
		fmt.Println("Starting HTTP server at port", port)
		ec <- http.ListenAndServe(port, httpHandler)
	}()

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		ec <- fmt.Errorf("%s", <-c)
	}()
	fmt.Println(<-ec)
}
