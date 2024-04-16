package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// URL to upload the Credentials to the database
const (            
	serverURL      = "http://localhost:8000/api/logs" 
	signatureAgent = "DemoSignTool"
)

// Payload represents the JSON payload structure of Credentials to be uploaded to the Database.
type Payload struct {
	FileName           string `json:"name"`
	Hash       string `json:"hash"`
	SignedReference string `json:"signedReference"`
	KeyName        string `json:"keyName"`
	SignAgent        string `json:"signAgent"`
}

// SignFile signs the content of a file using RSA private key, further it creates a hash of the file aswell as 
// returns the signature reference of the file.
func SignFile(filePath string, privateKey *rsa.PrivateKey) ([]byte, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(content)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// UploadPayload function uploads the payload to the server
func UploadPayload(payload *Payload) error {
	// Encode payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Send HTTP POST request to server
	_, err = http.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	return nil
}

// parsePrivateKey parses RSA private key from bytes
func parsePrivateKey(privateKeyBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) 
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA private key")
	}

	return rsaPrivateKey, nil
}

func main() {
	// Get private key path and file path from command line argument and asign to variables
	if len(os.Args) < 3 {
		fmt.Println("Usage: ./sign-and-upload <key_file> <file>")
		os.Exit(1)
	}
	privateKeyFile := os.Args[1]
	filePath := os.Args[2]

	// Read private key from file in bytes
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		fmt.Println("Error reading private key file:", err)
		os.Exit(1)
	}

	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		os.Exit(1)
	}

	// Read file content from file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

	// Generate a sha256 hash of the file and create a hex string
	hash := sha256.Sum256(content)
	hashString := hex.EncodeToString(hash[:])
	fmt.Println("Hash of the file:", hashString)

	// Sign file using the user provided private key
	signature, err := SignFile(filePath, privateKey)
	if err != nil {
		fmt.Println("Error signing file:", err)
		os.Exit(1)
	}

	// Encode signature to base64
	signedReference := base64.StdEncoding.EncodeToString(signature)

	// Prepare payload to upload to server
	payload := &Payload{
		FileName:           filePath,
		Hash:       hashString,
		SignedReference: signedReference,
		KeyName:        privateKeyFile,
		SignAgent:        signatureAgent,
	}

	// Upload payload to server
	err = UploadPayload(payload)
	if err != nil {
		fmt.Println("Error uploading payload:", err)
		os.Exit(1)
	}

	fmt.Println("Payload uploaded successfully!")
}