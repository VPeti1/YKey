# YKey

YKey is a command-line tool for generating and managing encryption keys, creating file signatures, encrypting and decrypting files, and verifying file authenticity

# Installation
## Download the installer or compile it yourself
## Make it executable
chmod +x installer
## Run it
./installer

# Syntax
    create: Generates a new pair of public and private keys.
        Usage: ykey create
    createsig: Creates a signature for a specified file.
        Usage: ykey createsig <filename>
    verify: Verifies the authenticity of a file using its signature.
        Usage: ykey verify <filename> [<ykey hash> <issuer's public key>]
    regen: Regenerates keys. You can choose to use a custom encryption word or not.
        Usage: ykey regen [<encryption word>]
    encrypt: Encrypts a file using the generated private key.
        Usage: ykey encrypt <filename>
    decrypt: Decrypts a previously encrypted file using the private key.
        Usage: ykey decrypt <filename> <private key>

# Features

    Key Generation: Easily generate a pair of public and private keys for encryption and decryption.
    File Signing: Create a signature for a file to ensure its authenticity.
    File Encryption: Encrypt files using the generated private key for secure storage or transmission.
    File Decryption: Decrypt previously encrypted files using the private key.
    Verification: Verify the authenticity of a file by checking its signature against the provided key.

# Examples

## Generate a new key pair:

    ykey create

## Create a signature for a file:

    ykey createsig myfile.txt

## Verify the authenticity of a file:

    ykey verify myfile.txt

## Regenerate keys with a custom encryption word:

    ykey regen mycustomword

## Encrypt a file:

    ykey encrypt myfile.txt

## Decrypt a file:

    ykey decrypt myfile.txt myprivatekey

