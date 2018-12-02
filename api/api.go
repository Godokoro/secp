package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/pborman/uuid"
	"github.com/sethvargo/go-diceware/diceware"
	"golang.org/x/crypto/scrypt"
)

// Empty improves readability
var Empty string

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

const (
	// JWTAlgorithm is for secp256k1
	JWTAlgorithm    string = "ES256"
	maxKeystoreSize int64  = 1024
	version                = 3
	defaultExpiry   string = "1h"
)

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

const (
	keyHeaderKDF = "scrypt"

	scryptR     = 8
	scryptDKLen = 32
)

func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func encryptKey(key *ecdsa.PrivateKey, address *common.Address, id uuid.UUID, auth string, scryptN, scryptP int) ([]byte, error) {
	authArray := []byte(auth)

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	derivedKey, err := scrypt.Key(authArray, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return nil, err
	}
	encryptKey := derivedKey[:16]
	keyBytes := math.PaddedBigBytes(key.D, 32)

	iv := make([]byte, aes.BlockSize) // 16
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	if err != nil {
		return nil, err
	}
	mac := crypto.Keccak256(derivedKey[16:32], cipherText)

	scryptParamsJSON := make(map[string]interface{}, 5)
	scryptParamsJSON["n"] = scryptN
	scryptParamsJSON["r"] = scryptR
	scryptParamsJSON["p"] = scryptP
	scryptParamsJSON["dklen"] = scryptDKLen
	scryptParamsJSON["salt"] = hex.EncodeToString(salt)

	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	cryptoStruct := cryptoJSON{
		Cipher:       "aes-128-ctr",
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          keyHeaderKDF,
		KDFParams:    scryptParamsJSON,
		MAC:          hex.EncodeToString(mac),
	}
	encryptedKeyJSONV3 := encryptedKeyJSONV3{
		hex.EncodeToString(address[:]),
		cryptoStruct,
		id.String(),
		version,
	}
	return json.Marshal(encryptedKeyJSONV3)
}

func writeKeyFile(file string, content []byte) error {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()
	return os.Rename(f.Name(), file)
}

func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}

// ZeroKey removes a private key from memory
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

// CreateKeystore creates a JSON encrypted keystore and returns a generated passphrase
func CreateKeystore(path string, words int, separator string) (string, string, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return Empty, Empty, nil
	}
	defer ZeroKey(privateKey)
	id := uuid.NewRandom()

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	list, _ := diceware.Generate(words)
	passphrase := strings.Join(list, separator)
	jsonBytes, err := encryptKey(privateKey, &address, id, passphrase, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		return Empty, Empty, nil
	}
	path = filepath.Join(path, keyFileName(address))

	writeKeyFile(path, jsonBytes)
	return path, passphrase, nil
}

// KeyFromKeystore decrypts a JSON encrypted keystore and returns the private key
func KeyFromKeystore(path string, passphrase string) (*ecdsa.PrivateKey, error) {
	var key *keystore.Key
	jsonKeystore, err := readJSONKeystore(path)
	if err != nil {
		return nil, err
	}
	key, err = keystore.DecryptKey(jsonKeystore, passphrase)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("failed to decrypt key")
	}

	return key.PrivateKey, err
}

func readJSONKeystore(path string) ([]byte, error) {
	var jsonKeystore []byte
	file, err := os.Open(path)
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() > maxKeystoreSize {
		err = fmt.Errorf("keystore is suspiciously large at %d bytes", stat.Size())
		return nil, err
	}
	jsonKeystore, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jsonKeystore, nil

}

func claim(claims map[string]interface{}, key string) string {
	if claims != nil {
		if claim, ok := claims[key]; ok {
			return claim.(string)
		}
	}
	return Empty
}

func hashKeccak256(data string) []byte {
	input := []byte(data)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
	hash := crypto.Keccak256([]byte(msg))
	return hash
}

// Address returns an address
func Address(privateKey *ecdsa.PrivateKey) (string, error) {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return Empty, fmt.Errorf("cannot convert public key")
	}
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	hasher := sha3.NewKeccak256()
	hasher.Write(publicKeyBytes[1:])
	address := hexutil.Encode(hasher.Sum(nil)[12:])
	return address, nil
}

// CreateImmutabilityJWT creates an Immutability JWT
func CreateImmutabilityJWT(claimsData string, privateKey *ecdsa.PrivateKey) (string, error) {
	var claims jwt.MapClaims
	if claimsData != "" {
		if err := json.Unmarshal([]byte(claimsData), &claims); err != nil {
			return Empty, err
		}
	} else {
		claims = make(jwt.MapClaims)
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return Empty, fmt.Errorf("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	hasher := sha3.NewKeccak256()
	hasher.Write(publicKeyBytes[1:])
	address := hexutil.Encode(hasher.Sum(nil)[12:])

	claims["iss"] = address

	if claim(claims, "sub") == "" {
		claims["sub"] = address
	}
	if claim(claims, "nbf") == "" {
		claims["nbf"] = fmt.Sprintf("%d", time.Now().UTC().Unix())
	}
	timeUnix, err := strconv.ParseInt(claims["nbf"].(string), 10, 64)
	if err != nil {
		return Empty, err
	}
	if claim(claims, "exp") == "" {
		timeStart := time.Unix(timeUnix, 0)
		timeExpiry, err := time.ParseDuration(defaultExpiry)
		if err != nil {
			return Empty, err
		}
		claims["exp"] = fmt.Sprintf("%d", timeStart.Add(timeExpiry).Unix())
	}

	uniqueID := uuid.NewRandom()
	if err != nil {
		return Empty, err
	}
	hash := hashKeccak256(uniqueID.String())
	signature, err := crypto.Sign(hash, privateKey)

	alg := jwt.GetSigningMethod(JWTAlgorithm)
	if alg == nil {
		return Empty, fmt.Errorf("no signing method: %s", JWTAlgorithm)
	}
	claims["jti"] = uniqueID.String()
	claims["eth"] = hexutil.Encode(signature[:])
	// create a new JWT
	token := jwt.NewWithClaims(alg, claims)
	tokenOutput, err := token.SignedString(privateKey)
	if err != nil {
		return Empty, fmt.Errorf("failed to sign token: %v", err)
	}
	return tokenOutput, nil
}

// ParseImmutabilityJWT returns a public key derived from an Immutability JWT
func ParseImmutabilityJWT(rawToken string) (jwt.MapClaims, *ecdsa.PublicKey, error) {
	tokenWithoutWhitespace := regexp.MustCompile(`\s*$`).ReplaceAll([]byte(rawToken), []byte{})
	token := string(tokenWithoutWhitespace)

	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil || jwtToken == nil {
		return nil, nil, fmt.Errorf("cannot parse token")
	}
	unverifiedJwt := jwtToken.Claims.(jwt.MapClaims)
	if unverifiedJwt == nil {
		return nil, nil, fmt.Errorf("cannot get claims")
	}
	ethereumAddress := unverifiedJwt["iss"].(string)

	jti := unverifiedJwt["jti"].(string)
	signatureRaw := unverifiedJwt["eth"].(string)
	hash := hashKeccak256(jti)
	signature, err := hexutil.Decode(signatureRaw)

	if err != nil {
		return nil, nil, err
	}
	pubkey, err := crypto.SigToPub(hash, signature)

	if err != nil {
		return nil, nil, err
	}
	address := crypto.PubkeyToAddress(*pubkey)
	if strings.ToLower(ethereumAddress) == strings.ToLower(address.Hex()) {
		validateJwt, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			return pubkey, nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf(err.Error())
		}
		claims := validateJwt.Claims.(jwt.MapClaims)
		err = claims.Valid()
		if err != nil {
			return nil, nil, err
		}
		return claims, pubkey, nil
	}
	return nil, nil, fmt.Errorf("error verifying token")
}

// Encrypt plaintext
func Encrypt(plaintext string, publicKey *ecdsa.PublicKey) (string, error) {
	publicKeyBytes := crypto.FromECDSAPub(publicKey)

	pubKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return Empty, err
	}

	ciphertextBytes, err := btcec.Encrypt(pubKey, []byte(plaintext))
	if err != nil {
		return Empty, err
	}
	ciphertext := hexutil.Encode(ciphertextBytes)
	return ciphertext, nil
}

// Decrypt ciphertext
func Decrypt(ciphertext string, privateKey *ecdsa.PrivateKey) (string, error) {
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)
	ciphertextBytes, err := hexutil.Decode(ciphertext)
	if err != nil {
		return Empty, err
	}
	plaintext, err := btcec.Decrypt(privKey, ciphertextBytes)
	if err != nil {
		return Empty, err
	}
	return string(plaintext), nil
}

// Decode returns the claims
func Decode(token string) (jwt.MapClaims, error) {
	tokenWithoutWhitespace := regexp.MustCompile(`\s*$`).ReplaceAll([]byte(token), []byte{})
	unverifiedJwt, _, err := new(jwt.Parser).ParseUnverified(string(tokenWithoutWhitespace), jwt.MapClaims{})
	claims := unverifiedJwt.Claims.(jwt.MapClaims)
	if err == nil {
		return claims, nil
	}
	return nil, err

}
