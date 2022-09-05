// Copyright 2022 PingCAP, Inc.
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

package config

import (
	"testing"
	"time"

	"github.com/pingcap/TiProxy/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestProxyConfig(t *testing.T) {
	cfgmgr, ctx := testConfigManager(t, config.ConfigManager{
		IgnoreWrongNamespace: true,
	})

	cases := []*config.ProxyServerOnline{
		{
			MaxConnections: 1,
			TCPKeepAlive:   false,
		},
		{
			MaxConnections: 1,
			TCPKeepAlive:   true,
		},
		{
			MaxConnections: 0,
			TCPKeepAlive:   false,
		},
		{
			MaxConnections: 0,
			TCPKeepAlive:   true,
		},
	}
	ch := cfgmgr.GetProxyConfig()
	for _, tc := range cases {
		require.NoError(t, cfgmgr.SetProxyConfig(ctx, tc))
		select {
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting chan")
		case tg := <-ch:
			require.Equal(t, tc, tg)
		}
	}
}