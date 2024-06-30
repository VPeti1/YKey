# YKey

YKey is a command-line tool for key generation, file signing, verification, encryption, and decryption using AES encryption and HMAC-SHA256 signatures

## Usage

    ykey generate 
    ykey sign <file> 
    ykey verify <filepath> <filesigpath> 
    ykey encrypt <filename> 
    ykey decrypt <filename>

## Commands

    generate: Generates cryptographic keys and saves them securely.
    sign <file>: Signs a specified file using HMAC-SHA256.
    verify <filepath> <filesigpath>: Verifies the signature of a file.
    encrypt <filename>: Encrypts a file using AES encryption.
    decrypt <filename>: Decrypts a file previously encrypted with YKey.

## Security Considerations

    Password Security: Always use strong passwords for key operations.
    File Integrity: Ensure files are not tampered with by verifying signatures.
    Key Management: Safeguard generated keys (private.key and public.key).

## How Signing Works:

Key Pair: A digital signature uses a private-public key pair:
        Private Key: Known only to the signer, it creates the signature, encrypts and decryps.
        Public Key: Available publicly, it verifies the signature.

### Verification:
Recipients use the sender's public key to decrypt the signature and obtain the original hash.
They hash the received data to get a new hash value.
        If both hashes match, the data is authentic and unchanged.

## Why Signing Cannot Be Reversed:

One-Way Hashing: The hash function irreversibly converts data into a fixed-size hash. It's computationally impractical to derive the original data from the hash.

Private Key Security: Only the signer's private key can create a valid signature. Without it, forging or reversing the signature is extremely difficult.

Cryptographic Strength: Modern signing algorithms are designed with strong encryption methods, ensuring that even with computational power, reversing the process without the private key is virtually impossible.