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
	"github.com/joho/godotenv"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// URLs and constants(signing agent) for the application
const (
	loginURL       = "http://localhost:8000/api/users/login"
	logsURL        = "http://localhost:8000/api/logs"
	signatureAgent = "SigNature"
)

// Payload represents the JSON payload structure of Credentials to be uploaded to the Database.
type Payload struct {
	FileName        string `json:"name"`
	Hash            string `json:"hash"`
	SignedReference string `json:"signedReference"`
	KeyName         string `json:"keyName"`
	SignAgent       string `json:"signAgent"`
	File			[]byte `json:"file"`
	KeyFile 		[]byte `json:"keyFile"`
}

// SignFile signs the content of a file using RSA private key, further it creates a hash of the file as well as
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
func UploadPayload(payload *Payload, token string) error {
	// Encode payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Create a new HTTP client
	client := &http.Client{}

	// Create a new request with the payload data
	req, err := http.NewRequest("POST", logsURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set the content type header
	req.Header.Set("Content-Type", "application/json")
	// Set the Authorization header with the token
	req.Header.Set("Authorization", "Bearer "+token)
	// Send the request to the server
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check the response status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %s", resp.Status)
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

// Login function performs user login and returns the token
func Login(email, password string) (string, error) {
	// Prepare login payload with email and password in JSON format
	loginPayload := map[string]string{"email": email, "password": password}
	loginData, err := json.Marshal(loginPayload)
	if err != nil {
		return "", err
	}
	// Send login request to the server
	resp, err := http.Post(loginURL, "application/json", bytes.NewBuffer(loginData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check response status code after login request
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed: %s", resp.Status)
	}
	// Decode login response and extract the token from it
	var loginResponse map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		return "", err
	}

	//set the token
	token, ok := loginResponse["accessToken"]
	if !ok {
		return "", fmt.Errorf("accessToken not found in login response")
	}

	return token, nil
}

// VerifyFile verifies the signature of the file using the rsa public key
func VerifyFile(filePath string, publicKey *rsa.PublicKey) error {
	// Read the file to be verified
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Extract the hash and signature from the file's metadata
	var hash, signature []byte
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Hash:") {
			hash, err = hex.DecodeString(strings.TrimSpace(line[len("Hash:"):]))
			if err != nil {
				return fmt.Errorf("error decoding hash: %w", err)
			}
		}
		if strings.HasPrefix(line, "SignedReference:") {
			signature, err = base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("SignedReference:"):]))
			if err != nil {
				return fmt.Errorf("error decoding signature: %w", err)
			}
		}
	}

	// Verify the signature against the hash using the rsa public key
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}


// parsePublicKey parses RSA public key from bytes
func parsePublicKey(publicKeyBytes []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(publicKeyBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to parse PEM block containing the public key")
    }

    // Parse public key using ParsePKIXPublicKey
    publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %w", err)
    }

    // Type assert the parsed public key to *rsa.PublicKey
    publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
    if !ok {
        return nil, fmt.Errorf("failed to convert public key to RSA public key")
    }

    return publicKey, nil
}

// LoadPublicKey loads RSA public key from file
func LoadPublicKey(publicKeyFile string) (*rsa.PublicKey, error) {
	// Read public key file into bytes
	publicKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %w", err)
	}

	// Parse public key from bytes
	publicKey, err := parsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	return publicKey, nil
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	if len(os.Args) < 3 {
		fmt.Println("Usage: ./SigNature <commands>")
		fmt.Println("Commands:")
		fmt.Println("  sign -priv <private_key_file> -pub <public_key_file> -f <file>")
		fmt.Println("  verify -pub <public_key_file> -f <file>")
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "sign":
		if len(os.Args) < 8 {
			fmt.Println("Usage: ./SigNature sign -priv <private_key_file> -pub <public_key_file> -f <file>")
			os.Exit(1)
		}
		privateKeyFile := os.Args[3]
		publicKeyfile := os.Args[5]
		filePath := os.Args[7]

		// Read private key file set to bytes variable
		privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
		if err != nil {
			fmt.Println("Error reading private key file:", err)
			os.Exit(1)
		}

		publicKeyBytes, err := ioutil.ReadFile(publicKeyfile)
		if err != nil {
			fmt.Println("Error reading private key file:", err)
			os.Exit(1)
		}

		// Parse private key from bytes variable
		privateKey, err := parsePrivateKey(privateKeyBytes)
		if err != nil {
			fmt.Println("Error parsing private key:", err)
			os.Exit(1)
		}

		// Sign file using the user provided private key
		signature, err := SignFile(filePath, privateKey)
		if err != nil {
			fmt.Println("Error signing file:", err)
			os.Exit(1)
		}

		// Encode signature to base64
		signedReference := base64.StdEncoding.EncodeToString(signature)

		// Generate a sha256 hash of the file and create a hex string
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			os.Exit(1)
		}

		hash := sha256.Sum256(content)
		hashString := hex.EncodeToString(hash[:])
		fmt.Println("Hash of the file:", hashString)

		// Write the signature reference and hash to the file's metadata
		metadata := []byte(fmt.Sprintf("SignedReference: %s\nHash: %s\n", signedReference, hashString))
		contentWithMetadata := append(metadata, content...)

		// Write the file with metadata
		err = ioutil.WriteFile(filePath, contentWithMetadata, 0644)
		if err != nil {
			fmt.Println("Error writing file with metadata:", err)
			os.Exit(1)
		}

		fmt.Println("File signed successfully!")

		// Create the payload with the file name, hash, signature reference, public key name, signature agent, file content and public key file
		payload := &Payload{
			FileName:			filePath,
			Hash:				hashString,
			SignedReference:	signedReference,
			KeyName:			publicKeyfile,
			SignAgent:			signatureAgent,
			File:				content,
			KeyFile:			publicKeyBytes,
		}
	
		// Get email and password from environment variables
		email := os.Getenv("EMAIL")
		password := os.Getenv("PASSWORD")
	
		// Login using the email and password and retrieve token
		token, err := Login(email, password)
		if err != nil {
			fmt.Println("Error logging in:", err)
			os.Exit(1)
		}
	
		// Upload payload to server with the token in Authorization header
		err = UploadPayload(payload, token)
		if err != nil {
			fmt.Println("Error uploading payload:", err)
			os.Exit(1)
		}
	
		fmt.Println("Payload uploaded successfully!")

	case "verify":
		if len(os.Args) < 6 {
			fmt.Println("Usage: ./SigNature verify -pub <public_key_file> -f <file>")
			os.Exit(1)
		}
		publicKeyFile := os.Args[3]
		filePath := os.Args[5]

		// Load public key from file
		publicKey, err := LoadPublicKey(publicKeyFile)
		if err != nil {
			fmt.Println("Error loading public key:", err)
			os.Exit(1)
		}

		// Verify the signature of the file using the rsa public key
		err = VerifyFile(filePath, publicKey)
		if err != nil {
			fmt.Println("Error verifying file:", err)
			os.Exit(1)
		}

		fmt.Println("File verified successfully!")
	default:
		fmt.Println("Invalid command. Available commands: sign, verify")
		os.Exit(1)
	}
}
