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
	"os"

	"github.com/immutability-io/secp/api"
	"github.com/spf13/cobra"
)

// Ciphertext is the text to decrypt
var Ciphertext string

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypts an encrypted message using a keystore.",
	Long:  `Encrypts an encrypted message using a keystore.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return CheckRequiredFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		privateKey, err := api.KeyFromKeystore(Path, Passphrase)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		plaintext, err := api.Decrypt(Ciphertext, privateKey)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}
		address, err := api.Address(privateKey)
		if err != nil {
			fmt.Printf("{\"error\":\"%s\"}\n", err)
			os.Exit(1)
		}

		fmt.Printf("{\"address\":\"%s\",\"plaintext\":\"%s\"}\n", address, plaintext)
	},
}

func init() {
	decryptCmd.PersistentFlags().StringVar(&Path, "path", "", "Path to encrypted keystore (defaults to $HOME)")
	decryptCmd.MarkPersistentFlagRequired("path")
	decryptCmd.PersistentFlags().StringVar(&Passphrase, "passphrase", "", "Passphrase used to encrypt keystore")
	decryptCmd.MarkPersistentFlagRequired("passphrase")
	decryptCmd.PersistentFlags().StringVar(&Ciphertext, "ciphertext", "", "Ciphertext is the string to decrypt")
	decryptCmd.MarkPersistentFlagRequired("ciphertext")
	rootCmd.AddCommand(decryptCmd)
}
