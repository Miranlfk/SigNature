# SigNature
A mini executable/CLI tool to sign files and update Credential Logs. RSA private key and public key are generated using `openssl` can be used to sign and verify a file.

To build the executable:

```go build -o SigNature.exe```

Generate a rsa private and public keys using OpenSSL:

``` openssl genpkey -algorithm RSA -out <private_key_name>.pem -pkeyopt rsa_keygen_bits:2048 ```

``` openssl rsa -in <private_key_name>.pem -pubout -out <public_key_name>.pem ```

To use the executable:

```
Usage: ./SigNature <commands>
Commands:
  sign -priv <private_key_file> -pub <public_key_file> -f <file>
  verify -pub <public_key_file> -f <file>

```

### Sign

Use:

```./SigNature sign -priv <private_key_file> -pub <public_key_file> -f <file>```

As per the above command, the user provided file will be signed using the rsa private key under the SignPKCS1v15 format, further Metadata of "Hash:" or "SignedReference:" will be appended to the file. Further the File Name, File Hash Value, Signature Reference, Public Key Name, Key and the Signature Agent will be uploaded as a log to the CredentialLog via api call.  


### Verify

Use:

```./SigNature verify -pub <public_key_file> -f <file>```

As per the above command, the user provided file will be verified using the rsa public key under the VerifyPKCS1v15 format, further the VerifyFile function splits the file content into lines, the function can then iterate over each line and check if it starts with the metadata "Hash:" or "SignedReference:". If it does, it knows that the rest of the line after the prefix is the corresponding value. This value is then decoded from a hexadecimal string (for the hash) or a base64 string (for the signature) into a byte array. This approach allows for a flexible file structure where the hash and signature can appear in any order, and potentially additional metadata could be included in the same way. It assumes that each piece of metadata is on its own line and correctly prefixed.  
