// Copyright 2017 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package infra contains common definitions for the SCION infrastructure
// messaging layer.
package infra

import "github.com/scionproto/scion/go/lib/common"

const (
	StrCtxDoneError   = "context canceled"
	StrClosedError    = "layer closed"
	StrAdapterError   = "msg adapter error"
	StrInternalError  = "internal error"
	StrTransportError = "transport error"
)

// errMeta extends BasicError to include a timeout
type errMeta struct {
	common.BasicError
	timeout bool
}

func NewCtxDoneError(ctx ...interface{}) error {
	return &errMeta{
		BasicError: common.NewBasicError(StrCtxDoneError, nil, ctx...).(common.BasicError),
		timeout:    true,
	}
}

func (e errMeta) Timeout() bool {
	return e.timeout
}
