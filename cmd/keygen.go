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
	"fmt"

	"github.com/immutability-io/secp/api"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Creates a JSON encrypted keystore",
	Long: `Creates a JSON encrypted keystore and writes it to the (optionally) supplied path.

   * A strong passphrase is generated using an (optionally) user-supplied number of words and an (optionally) user supplied separator.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return CheckRequiredFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		filename, passphrase, err := api.CreateKeystore(Path, Words, Separator)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
		}
		fmt.Printf("{\"filename\":\"%s\",\"passphrase\":\"%s\"}\n", filename, passphrase)
	},
}

func init() {
	keygenCmd.PersistentFlags().StringVar(&Path, "path", "", "Path to encrypted keystore")
	keygenCmd.MarkPersistentFlagRequired("path")
	keygenCmd.PersistentFlags().StringVar(&Separator, "separator", "-", "The string to use as a separator for the passphrase (defaults to -)")
	keygenCmd.PersistentFlags().IntVar(&Words, "words", 6, "Number of words to use in passphrase (defaults to 6")
	rootCmd.AddCommand(keygenCmd)
}
