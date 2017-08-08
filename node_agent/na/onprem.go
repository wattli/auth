// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package na

import (
	"google.golang.org/grpc"
	"istio.io/auth/utils"
)

type onPremPlatformImpl struct {
}

func (na *onPremPlatformImpl) GetDialOptions(cfg *Config) ([]grpc.DialOption, error) {
	transportCreds := utils.GetTLSCredentials(*cfg.NodeIdentityCertFile,
		*cfg.NodeIdentityPrivateKeyFile,
		*cfg.RootCACertFile, true /* isClient */)
	var options []grpc.DialOption
	options = append(options, grpc.WithTransportCredentials(transportCreds))
	return options, nil
}

func (na *onPremPlatformImpl) IsProperPlatform() bool {
	return true
}
