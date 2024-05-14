package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	keyDir        = os.ExpandEnv("$HOME/.ykey/")
	privateKeyLoc = keyDir + "ykey.pri"
	publicKeyLoc  = keyDir + "ykey.pub"
)

const charset = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

func main() {
	fmt.Println(`____    ____  __  ___  ___________    ____ 
\   \  /   / |  |/  / |   ____\   \  /   / 
 \   \/   /  |  '  /  |  |__   \   \/   /  
  \_    _/   |    <   |   __|   \_    _/   
    |  |     |  .  \  |  |____    |  |     
    |__|     |__|\__\ |_______|   |__|`)
	time.Sleep(1 * time.Second)
	defVarForWin()
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Usage: ykey <create, createsig, verify, regen>")
		return
	}

	command := args[0]

	switch command {
	case "create":
		if len(args) > 1 {
			if args[1] == "force" {
				createKeyPair(true)
				return
			}
		}
		createKeyPair(false)
	case "createsig":
		if len(args) < 2 {
			fmt.Println("Usage: ykey createsig <filename>")
			return
		}
		filename := args[1]
		createSignature(filename)
	case "verify":
		if len(args) < 2 {
			fmt.Println("Usage: ykey verify <filename> [<ykey hash> <issuer's public key>]")
			return
		}
		filename := args[1]
		verifyFile(filename, args[2:]...)
	case "regen":
		if len(args) < 2 {
			fmt.Print("Do you want to create a custom key or not? ")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			custom := scanner.Text()
			if custom == "n" || custom == "no" {
				createKeyPair(true)
				return
			}
			fmt.Print("Enter encryption word (It can be anything): ")
			scanner2 := bufio.NewScanner(os.Stdin)
			scanner2.Scan()
			encryptionWord := scanner2.Text()
			regenerateKey(encryptionWord)
		}
		encword := args[1]
		regenerateKey(encword)
	case "encrypt":
		if len(args) < 2 {
			fmt.Println("Usage: ykey encrypt <filename>")
			return
		}
		filename := args[1]
		HandleEncrypt(filename)
	case "decrypt":
		if len(args) < 3 {
			fmt.Println("Usage: ykey decrypt <filename> <private key>")
			return
		}
		filename := args[1]
		key := args[2]
		HandleDecrypt(filename, key)
		return
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Usage: ykey <create, createsig, verify, regen>")
	}
}

func defVarForWin() {
	if detectOS() == "windows" {
		keyDir = "C:\\ProgramData\\ykey\\"
		privateKeyLoc = keyDir + "ykey.pri"
		publicKeyLoc = keyDir + "ykey.pub"
	}
}

func HandleEncrypt(filename string) {
	if !ykeyDirExists() {
		fmt.Println("You havent generated the key yet")
		return
	}
	pass, err := readFile(privateKeyLoc)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}
	passbyte := []byte(pass)
	Encrypt(filename, passbyte)
	fmt.Println("File encrypted succesfully")
	fmt.Println("Your private key is: " + pass)
}

func HandleDecrypt(filename string, key string) {
	if !ykeyDirExists() {
		fmt.Println("You havent generated the key yet")
		return
	}
	passbyte := []byte(key)
	Decrypt(filename, passbyte)
	fmt.Println("File decrypted succesfully")
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func ykeyDirExists() bool {
	if dirExists(keyDir) {
		return true
	} else {
		return false
	}
}

func createKeyPair(force bool) {
	if ykeyDirExists() {
		if !force {
			fmt.Println("You already generated the key")
			fmt.Println("If you want to regenerate the key use the 'regen' command")
			return
		}
	}

	var machineID []byte

	if detectOS() == "linux" {
		// Read machine ID from /etc/machine-id
		machineIDl, err := ioutil.ReadFile("/etc/machine-id")
		if err != nil {
			fmt.Println("Error reading machine ID:", err)
			return
		}
		machineID = machineIDl
	} else {
		interfaces, err := net.Interfaces()
		if err != nil {
			return
		}

		for _, intf := range interfaces {
			if intf.Flags&net.FlagLoopback == 0 && intf.HardwareAddr != nil {
				machineIDw := strings.Replace(intf.HardwareAddr.String(), ":", "", -1)
				machineID = []byte(machineIDw)
			}
		}
	}

	// Hash machine ID
	machineIDHash := sha256.Sum256(machineID)
	publicKeyHash := hex.EncodeToString(machineIDHash[:])
	privateKey := publicKeyHash + publicKeyHash
	privateKeyHash := CreateSHA256(privateKey)
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	// Save public key hash
	file, err := os.Create(publicKeyLoc)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(publicKeyHash)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	// Save private key hash
	file, err = os.Create(privateKeyLoc)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(privateKeyHash)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	fmt.Println("Keys generated and saved successfully.")

}

func readFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func getChars(s string) string {
	if len(s) < 6 {
		return s
	}
	return s[:6]
}

func CreateSHA256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hash := hasher.Sum(nil)
	hashstring := hex.EncodeToString(hash)
	return string(hashstring)
}

func createSignature(filename string) {
	if !ykeyDirExists() {
		fmt.Println("You havent generated the key yet")
		return
	}
	// Read file
	fileContent, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	hashstring := CreateSHA256(string(fileContent))
	publickey, err := readFile(publicKeyLoc)
	if err != nil {
		fmt.Println("Error reading public key:", err)
		return
	}
	publickeyhashed := CreateSHA256(publickey)
	hashstring6 := getChars(hashstring)
	publickey6 := getChars(publickeyhashed)
	random31 := RandomString(3)
	random32 := RandomString(3)
	ykeyHash := random31 + hashstring6 + publickey6 + random32
	fmt.Println("YKEY hash of the file '" + filename + "' is: " + ykeyHash)
	fmt.Println("Your public key is: " + publickey)

}

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		random, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[random.Int64()]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

func removeChars(s string) string {
	if len(s) < 6 {
		return ""
	}
	return s[3 : len(s)-3]
}

func verifyFile(filename string, args ...string) {
	var ykeyHash, publicKey string

	if len(args) == 2 {
		ykeyHash = args[0]
		publicKey = args[1]
	} else {
		fmt.Print("Enter YKEY hash: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		ykeyHash = scanner.Text()

		fmt.Print("Enter issuer's public key: ")
		scanner.Scan()
		publicKey = scanner.Text()
	}

	// Read file
	fileContent, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Get SHA256 sum of file
	fileHash := sha256.Sum256(fileContent)

	publicKeyHash := CreateSHA256(publicKey)
	fileHashs := hex.EncodeToString(fileHash[:])
	fileHash6 := getChars(string(fileHashs))
	publicKeyHash6 := getChars(publicKeyHash)
	ykeyHashrem := removeChars(ykeyHash)
	realhash := fileHash6 + publicKeyHash6

	if realhash == ykeyHashrem {
		fmt.Println("File is valid.")
	} else {
		fmt.Println("File is not valid.")
		fmt.Print("Do you want to delete it? ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		delreq := scanner.Text()
		if delreq == "y" || delreq == "yes" {
			err := os.Remove(filename)
			if err != nil {
				fmt.Println("Failed to delete file!")
				log.Fatal(err)
			} else {
				fmt.Println("File deleted succesfully")
			}

		}
	}
}

func detectOS() string {
	if runtime.GOOS == "linux" {
		return "linux"
	}
	return "windows"
}

func regenerateKey(encword string) {
	if !ykeyDirExists() {
		fmt.Println("You didnt generate a key yet!")
		return
	}

	var encryptionWord string

	if len(encword) == 0 {
		fmt.Print("Do you want to create a custom key or not? ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		custom := scanner.Text()
		if custom == "n" || custom == "no" {
			createKeyPair(true)
			return
		}
		fmt.Print("Enter encryption word (It can be anything): ")
		scanner2 := bufio.NewScanner(os.Stdin)
		scanner2.Scan()
		encryptionWord = scanner2.Text()
	} else {
		encryptionWord = encword
	}

	publicKeyHash := CreateSHA256(encryptionWord)

	privateKey := publicKeyHash + publicKeyHash
	privateKeyHash := CreateSHA256(privateKey)
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	// Save public key hash
	file, err := os.Create(publicKeyLoc)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(publicKeyHash)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	// Save private key hash
	file, err = os.Create(privateKeyLoc)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(privateKeyHash)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	fmt.Println("Keys generated and saved successfully.")
	fmt.Println("Your public key: " + publicKeyHash)
	fmt.Println("Your private key: " + privateKeyHash)
}

//Encrypt and Decrypt functions taken from: github.com/AkhilSharma90/go-file-encrypt

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
