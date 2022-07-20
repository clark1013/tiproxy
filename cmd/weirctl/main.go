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

package main

import (
	"net/http"

	"github.com/djshow832/weir/cmd/weirctl/namespace"
	"github.com/djshow832/weir/cmd/weirctl/util"
	"github.com/djshow832/weir/pkg/util/cmd"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "weirctl",
		Short: "cli",
	}

	ctx := &util.Context{}

	curls := rootCmd.PersistentFlags().StringArray("curls", []string{"localhost:2379"}, "API gateway addresses")
	logEncoder := rootCmd.PersistentFlags().String("log_encoder", "tidb", "log in format of tidb, console, or json")
	logLevel := rootCmd.PersistentFlags().String("log_level", "info", "log level")
	rootCmd.PersistentFlags().Bool("indent", true, "whether indent the returned json")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		zapcfg := zap.NewDevelopmentConfig()
		zapcfg.Encoding = *logEncoder
		if level, err := zap.ParseAtomicLevel(*logLevel); err == nil {
			zapcfg.Level = level
		}
		logger, err := zapcfg.Build()
		if err != nil {
			return err
		}
		ctx.Logger = logger.Named("cli")
		ctx.Client = &http.Client{}
		ctx.CUrls = *curls
		return nil
	}

	rootCmd.AddCommand(namespace.GetRootCommand(ctx))
	cmd.RunRootCommand(rootCmd)
}