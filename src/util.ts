import path from "node:path"
import fs from "node:fs"
import { stat } from "node:fs/promises";
import { askOverwritePermission, printWarning } from "./cli.ts";
/**
 * Derive an AES-GCM key from a given `passphrase`, `salt`, and `iterationCount`.
 * @param passphrase a human readable string used to derive the key
 * @param salt an array of 16 bytes which will be appended to `passphrase`
 * @param iterationCount specifies the number of PBDKF2 hash iterations performed to generate a base key
 * @param keyUsages array indicating what actions can be performed with the key. See [MDN Reference](https://developer.mozilla.org/docs/Web/API/SubtleCrypto/deriveKey)
 */
export async function deriveAESKeyFrom(
    passphrase: string, salt: Uint8Array<ArrayBuffer>, iterationCount: number, keyUsages: Iterable<KeyUsage>
): Promise<CryptoKey> {
    const passphraseBuffer = new TextEncoder().encode(passphrase);
    const baseKey = await crypto.subtle.importKey(
        "raw",
        passphraseBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: salt,
            iterations: iterationCount
        },
        baseKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        keyUsages
    );
}

/**
 * Attempt to open and read file at `path` into a `Uint8Array`
 */
export async function readInputFileBytes(filePath: string): Promise<Uint8Array<ArrayBuffer>> {
    const absolutePath = path.resolve(filePath);
    let bytes: Uint8Array<ArrayBuffer>;
    try {
        if (!fs.existsSync(absolutePath)) {
            printWarning("Error: No such file exists");
            process.exit(1);
        }
        if ((await stat(absolutePath)).isDirectory()) {
            printWarning("Error: Path is a directory");
            process.exit(1);
        }

        bytes = new Uint8Array(fs.readFileSync(absolutePath));
    } catch (e) {
        printWarning(`Error: could not read file: ${e}`);
        process.exit(1);
    }
    return bytes;
}
/**
 * Write `data` to file at `filePath`
 */
export function writeOutputFile(data: Uint8Array<ArrayBuffer>, filePath: string): void {
    try {
        fs.writeFileSync(filePath, data, 'utf8');
    } catch (e) {
        printWarning(`Error: could not write to file: ${e}`);
        process.exit(1);
    }
}
