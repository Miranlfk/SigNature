# signFilesforLog
A mini executable/CLI tool to sign files and update Credential Logs. A RSA private key generated using `openssl` can be used to sign a file as per this project. A user provided file will be read and signed using the user provided private key, the file name, hash value, signature reference and private key name will be uploaded as a log to the CredentialLog via api call.  
