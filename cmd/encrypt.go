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
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/immutability-io/secp/api"
	"github.com/spf13/cobra"
)

// Token is an Immutability format JWT
var Token string

// Plaintext is the text to encrypt
var Plaintext string

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypts a base64 encoded message using either a keystore or an Immutability format JWT.",
	Long:  `Encrypts a base64 encoded message using either a keystore or an Immutability format JWT.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return CheckRequiredFlags(cmd.Flags())
	},
	Run: func(cmd *cobra.Command, args []string) {
		if Token != "" {
			// Encrypt with public key derived from token
			claims, publicKey, err := api.ParseImmutabilityJWT(Token)
			if err != nil {
				fmt.Printf("{\"error\":\"%s\"}\n", err)
				os.Exit(1)
			}
			ciphertext, err := api.Encrypt(Plaintext, publicKey)
			if err != nil {
				fmt.Printf("{\"error\":\"%s\"}\n", err)
				os.Exit(1)
			}
			fmt.Printf("{\"address\":\"%s\",\"ciphertext\":\"%s\"}\n", claims["iss"], ciphertext)
			return
		} else if Path != "" || Passphrase != "" {
			privateKey, err := api.KeyFromKeystore(Path, Passphrase)
			if err != nil {
				fmt.Printf("{\"error\":\"%s\"}\n", err)
				os.Exit(1)
			}
			publicKey := privateKey.Public()
			publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
			if !ok {
				fmt.Printf("{\"error\":\"cannot convert public key\"}\n")
				os.Exit(1)
			}
			ciphertext, err := api.Encrypt(Plaintext, publicKeyECDSA)
			if err != nil {
				fmt.Printf("{\"error\":\"%s\"}\n", err)
				os.Exit(1)
			}
			address, err := api.Address(privateKey)
			if err != nil {
				fmt.Printf("{\"error\":\"%s\"}\n", err)
				os.Exit(1)
			}

			fmt.Printf("{\"address\":\"%s\",\"ciphertext\":\"%s\"}\n", address, ciphertext)
			return
		}
		fmt.Printf("{\"error\":\"missing keystore or passphrase\"}\n")

	},
}

func init() {
	encryptCmd.PersistentFlags().StringVar(&Path, "path", "", "Path to encrypted keystore (defaults to $HOME)")
	encryptCmd.PersistentFlags().StringVar(&Passphrase, "passphrase", "", "Passphrase used to encrypt keystore")
	encryptCmd.PersistentFlags().StringVar(&Token, "token", "", "Token is an Immutability JWT")
	encryptCmd.PersistentFlags().StringVar(&Plaintext, "plaintext", "", "Plaintext is the base64 encoded string to encrypt")
	encryptCmd.MarkPersistentFlagRequired("plaintext")
	rootCmd.AddCommand(encryptCmd)

}
