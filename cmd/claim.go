// Copyright © 2018 Immutability LLC
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

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/immutability-io/secp/api"
	"github.com/spf13/cobra"
)

// Values is a JSON encoded map of values
var Values string

// claimCmd represents the claim command
var claimCmd = &cobra.Command{
	Use:   "claim",
	Short: "Creates an Immutability encoded JWT using a passphrase encoded private key.",
	Long:  `Creates an Immutability encoded JWT using a passphrase encoded private key.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return CheckRequiredFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		decoded, err := base64.StdEncoding.DecodeString(Values)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		privateKey, err := api.KeyFromKeystore(Path, Passphrase)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		jwt, err := api.CreateImmutabilityJWT(string(decoded), privateKey)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		message, err := api.Decode(jwt)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		fmt.Printf("{\"token\":\"%s\",\"decoded\":%s}\n", jwt, api.PrettyPrint(message))
	},
}

func init() {
	claimCmd.PersistentFlags().StringVar(&Path, "path", "", "Path to encrypted keystore (defaults to $HOME)")
	claimCmd.PersistentFlags().StringVar(&Passphrase, "passphrase", "", "Passphrase used to encrypt keystore")
	claimCmd.MarkPersistentFlagRequired("passphrase")
	claimCmd.PersistentFlags().StringVar(&Values, "values", "", "Values is a base64 encoded JSON  map of values")
	claimCmd.MarkPersistentFlagRequired("values")
	rootCmd.AddCommand(claimCmd)
}
