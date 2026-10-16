# file-encrypt

A small command line tool that encrypts and decrypts files with a passphrase.

## Requirements

- Node.js 22.18 or newer (it runs the TypeScript files directly, with no build step)

## Setup

```sh
npm install
```

## Usage

Encrypt a file:

```sh
node src/main.ts encrypt <inputFile> <outputFile>
```

Decrypt a file:

```sh
node src/main.ts decrypt <inputFile> <outputFile>
```

You will be asked for a passphrase. It must be at least 8 characters. When encrypting, you type it twice to confirm. Press `ENTER` on an empty prompt to cancel.

If the output file already exists, you will be asked before it gets overwritten.

## How it works

- Your passphrase is turned into a 256-bit AES key using PBKDF2 (SHA-256, 600,000 rounds) and a random salt.
- The file is encrypted with AES-GCM. This also detects if the encrypted file was changed or the passphrase is wrong.
- A 37-byte header is placed at the start of the encrypted file:

| Bytes | Field              |
| ----- | ------------------ |
| 0-3   | Magic bytes `FENC` |
| 4     | Format version     |
| 5-8   | PBKDF2 rounds      |
| 9-24  | Salt (16 bytes)    |
| 25-36 | IV (12 bytes)      |

The header is not secret, but it is protected by AES-GCM, so any change to it makes decryption fail.
