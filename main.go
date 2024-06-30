package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/pbkdf2"
)

var keyDir string

func initPath() {
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		keyDir = filepath.Join(appData, "ykey")
	default:
		homeDir, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("error getting home directory: %v\n", err)
			return
		}
		keyDir = filepath.Join(homeDir, ".ykey")
	}
}

func detectMachineID() ([]byte, error) {
	switch runtime.GOOS {
	case "windows":
		interfaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("error getting network interfaces: %v", err)
		}

		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp != 0 && len(iface.HardwareAddr) > 0 {
				return []byte(iface.HardwareAddr.String()), nil
			}
		}

		return nil, fmt.Errorf("no suitable network interface found")
	default:
		machineID, err := ioutil.ReadFile("/etc/machine-id")
		if err != nil {
			return nil, fmt.Errorf("error reading /etc/machine-id: %v", err)
		}
		return machineID, nil
	}
}

func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func generateKeys() (string, string, error) {
	machineID, err := detectMachineID()
	if err != nil {
		return "", "", fmt.Errorf("error detecting machine ID: %v", err)
	}

	// Prompt for password and confirm password
	password, err := readPassword("Enter password: ")
	if err != nil {
		return "", "", fmt.Errorf("error reading password: %v", err)
	}

	confirmPassword, err := readPassword("Confirm password: ")
	if err != nil {
		return "", "", fmt.Errorf("error reading password confirmation: %v", err)
	}

	if password != confirmPassword {
		return "", "", fmt.Errorf("passwords do not match")
	}

	// Generate private key as machine ID + random bytes
	privateKey := append(machineID, make([]byte, 32)...)
	if _, err := rand.Read(privateKey[len(machineID):]); err != nil {
		return "", "", fmt.Errorf("error generating random bytes: %v", err)
	}

	// Generate public key by hashing private key
	publicKey := sha256.Sum256(privateKey)

	// Encrypt private key with password
	encryptedPrivateKey, err := encrypt(privateKey, password)
	if err != nil {
		return "", "", fmt.Errorf("error encrypting private key: %v", err)
	}

	return hex.EncodeToString(encryptedPrivateKey), hex.EncodeToString(publicKey[:]), nil
}

func saveKeys(encryptedPrivateKey string, publicKey string) error {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return fmt.Errorf("error creating key directory: %v", err)
	}

	// Save private key
	privateKeyPath := filepath.Join(keyDir, "private.key")
	if err := ioutil.WriteFile(privateKeyPath, []byte(encryptedPrivateKey), 0600); err != nil {
		return fmt.Errorf("error writing private key file: %v", err)
	}

	// Save public key
	publicKeyPath := filepath.Join(keyDir, "public.key")
	if err := ioutil.WriteFile(publicKeyPath, []byte(publicKey), 0644); err != nil {
		return fmt.Errorf("error writing public key file: %v", err)
	}

	return nil
}

func encrypt(data []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("error generating IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

func decrypt(cipherText []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return nil, fmt.Errorf("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return cipherText, nil
}

func signFile(filePath string, privateKey string) (string, error) {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	// Decode private key from hex
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("error decoding private key: %v", err)
	}

	// Decrypt private key with password
	decryptedPrivateKey, err := decrypt(privateKeyBytes, getPassword())
	if err != nil {
		return "", fmt.Errorf("error decrypting private key: %v", err)
	}

	// Compute HMAC-SHA256
	h := hmac.New(sha256.New, decryptedPrivateKey)
	h.Write(fileContent)
	signature := h.Sum(nil)

	return hex.EncodeToString(signature), nil
}

func verifyFileSignature(filePath, fileSigPath string, publicKey string) (bool, error) {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("error reading file: %v", err)
	}

	signatureContent, err := ioutil.ReadFile(fileSigPath)
	if err != nil {
		return false, fmt.Errorf("error reading signature file: %v", err)
	}

	// Decode the signature
	expectedSignature, err := hex.DecodeString(strings.TrimSpace(string(signatureContent)))
	if err != nil {
		return false, fmt.Errorf("error decoding signature: %v", err)
	}

	// Create an HMAC with SHA-256 using the public key
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, fmt.Errorf("error decoding public key: %v", err)
	}

	h := hmac.New(sha256.New, publicKeyBytes)
	h.Write(fileContent)
	expectedSignatureBytes := h.Sum(nil)

	// Compare the provided signature with the expected signature
	return hmac.Equal(expectedSignatureBytes, expectedSignature), nil
}

func getPassword() string {
	fmt.Print("Enter password: ")
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Println("Error reading password:", err)
		os.Exit(1)
	}
	return string(password)
}

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: ykey <command>")
		fmt.Println("Commands:")
		fmt.Println("  generate")
		fmt.Println("  sign <file>")
		fmt.Println("  verify <filepath> <filesigpath>")
		fmt.Println("  encrypt <filepath>")
		fmt.Println("  decrypt <filepath>")
		return
	}

	command := flag.Arg(0)
	args := os.Args[1:]
	initPath()

	switch command {
	case "generate":
		if ykeyDirExists() {
			fmt.Println("You have already generated the keys! If you want to regenerate them run 'ykey regen'")
			return
		}
		privateKey, publicKey, err := generateKeys()
		if err != nil {
			fmt.Println("Error generating keys:", err)
			return
		}

		if err := saveKeys(privateKey, publicKey); err != nil {
			fmt.Println("Error saving keys:", err)
			return
		}

		fmt.Println("Keys generated and saved successfully.")

	case "regen":
		if !ykeyDirExists() {
			fmt.Println("You havent generated the keys yet")
			return
		}
		err := os.RemoveAll(keyDir)
		if err != nil {
			fmt.Printf("Error deleting directory %s: %v\n", keyDir, err)
			return
		}
		privateKey, publicKey, err := generateKeys()
		if err != nil {
			fmt.Println("Error generating keys:", err)
			return
		}

		if err := saveKeys(privateKey, publicKey); err != nil {
			fmt.Println("Error saving keys:", err)
			return
		}

		fmt.Println("Keys generated and saved successfully.")

	case "sign":
		if !ykeyDirExists() {
			fmt.Println("You havent generated the keys yet")
			return
		}
		if flag.NArg() < 2 {
			fmt.Println("Usage: ykey sign <file>")
			return
		}

		filePath := flag.Arg(1)

		privateKeyPath := filepath.Join(keyDir, "private.key")
		privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}

		signature, err := signFile(filePath, string(privateKeyBytes))
		if err != nil {
			fmt.Println("Error signing file:", err)
			return
		}

		signatureFilePath := filePath + ".ysig"
		if err := ioutil.WriteFile(signatureFilePath, []byte(signature), 0644); err != nil {
			fmt.Println("Error writing signature file:", err)
			return
		}

		fmt.Println("File signed successfully. Signature saved to:", signatureFilePath)

	case "verify":
		if flag.NArg() < 3 {
			fmt.Println("Usage: ykey verify <filepath> <filesigpath>")
			return
		}

		filePath := flag.Arg(1)
		fileSigPath := flag.Arg(2)

		publicKeyPath := filepath.Join(keyDir, "public.key")
		publicKeyBytes, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			fmt.Println("Error reading public key:", err)
			return
		}

		isValid, err := verifyFileSignature(filePath, fileSigPath, string(publicKeyBytes))
		if err != nil {
			fmt.Println("Error verifying signature:", err)
			return
		}

		if isValid {
			fmt.Println("The signature is valid.")
		} else {
			fmt.Println("The signature is not valid.")
		}

	case "encrypt":
		if len(args) < 2 {
			fmt.Println("Usage: ykey encrypt <filename>")
			return
		}
		filename := args[1]
		HandleEncrypt(filename)
	case "decrypt":
		if len(args) < 2 {
			fmt.Println("Usage: ykey decrypt <filename>")
			return
		}
		filename := args[1]
		HandleDecrypt(filename)
		return

	default:
		fmt.Println("Unknown command:", command)
	}
}

func Encrypt(source string, password []byte) {

	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	plaintext, err := ioutil.ReadFile(source)

	if err != nil {
		panic(err.Error())
	}

	key := password
	nonce := make([]byte, 12)

	// Randomizing the nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// Append the nonce to the end of file
	ciphertext = append(ciphertext, nonce...)

	f, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(ciphertext))
	if err != nil {
		panic(err.Error())
	}
}

func Decrypt(source string, password []byte) {

	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}

	ciphertext, err := ioutil.ReadFile(source)

	if err != nil {
		panic(err.Error())
	}

	key := password
	salt := ciphertext[len(ciphertext)-12:]
	str := hex.EncodeToString(salt)

	nonce, err := hex.DecodeString(str)

	if err != nil {
		panic(err.Error())
	}

	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	f, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(plaintext))
	if err != nil {
		panic(err.Error())
	}
}

func HandleEncrypt(filename string) {
	if !ykeyDirExists() {
		fmt.Println("You havent generated the keys yet")
		return
	}

	privateKeyPath := filepath.Join(keyDir, "private.key")
	privateKey, err := ioutil.ReadFile(privateKeyPath)

	// Decode private key from hex
	privateKeyBytes, err := hex.DecodeString(string(privateKey))
	if err != nil {
		fmt.Printf("error decoding private key: %v\n", err)
		return
	}

	// Decrypt private key with password
	decryptedPrivateKey, err := decrypt(privateKeyBytes, getPassword())
	if err != nil {
		fmt.Printf("error decrypting private key: %v\n", err)
		return
	}

	pass := decryptedPrivateKey
	passbyte := []byte(pass)
	Encrypt(filename, passbyte)
	fmt.Println("File encrypted succesfully")
}

func HandleDecrypt(filename string) {
	if !ykeyDirExists() {
		fmt.Println("You havent generated the keys yet")
		return
	}
	privateKeyPath := filepath.Join(keyDir, "private.key")
	privateKey, err := ioutil.ReadFile(privateKeyPath)

	// Decode private key from hex
	privateKeyBytes, err := hex.DecodeString(string(privateKey))
	if err != nil {
		fmt.Printf("error decoding private key: %v\n", err)
		return
	}

	// Decrypt private key with password
	decryptedPrivateKey, err := decrypt(privateKeyBytes, getPassword())
	if err != nil {
		fmt.Printf("error decrypting private key: %v\n", err)
		return
	}

	pass := decryptedPrivateKey
	passbyte := []byte(pass)
	Decrypt(filename, passbyte)
	fmt.Println("File decrypted succesfully")
}

func ykeyDirExists() bool {
	if dirExists(keyDir) {
		return true
	} else {
		return false
	}
}
