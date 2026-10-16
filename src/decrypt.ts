import { printWarning } from "./cli.ts";
import type { EncryptionHeader, EncryptionHeaderProperties } from "./types.ts";
import { deriveAESKeyFrom } from "./util.ts";

const INVALID_FILE = "ERROR: Invalid file format";
const DECRYPTION_ERR = "ERROR: Could not decrypt file. The passphrase may be incorrect, or the file has been tampered with."

export default async function decrypt(
    inputBytes: Uint8Array<ArrayBuffer>, passphrase: string, props: EncryptionHeaderProperties
): Promise<Uint8Array<ArrayBuffer>> {
    const header: EncryptionHeader | null = parseEncryptionHeader(inputBytes, props);
    if (!header) process.exit(1);
    const derivedAESKey = await deriveAESKeyFrom(passphrase, header.salt, header.PBDKF2Iterations, ["decrypt"]);
    let ciphertext;
    try {
        ciphertext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: header.iv,
                additionalData: inputBytes.subarray(0, props.byteLength)
            },
            derivedAESKey,
            inputBytes.subarray(props.byteLength)
        );
    } catch (e) {
        printWarning(DECRYPTION_ERR);
        process.exit(1)
    }
    return new Uint8Array(ciphertext);
}

function parseEncryptionHeader(
    inputBytes: Uint8Array<ArrayBuffer>, props: EncryptionHeaderProperties
): EncryptionHeader | null {
    if (inputBytes.length < props.byteLength) { // file length is shorter than header length -> invalid file
        printWarning(INVALID_FILE);
        return null;
    }
    const magicBytes = inputBytes.slice(0, props.offsets.VERSION_BYTE_OFFSET);
    if (!compareBytes(magicBytes, props.magicBytes)) { // magic bytes do not match -> invalid file
        printWarning(INVALID_FILE);
        return null;
    }
    const versionByte = inputBytes[props.offsets.VERSION_BYTE_OFFSET];
    if (!props.versionByteList.includes(versionByte)) { // version byte not in version byte list -> invalid file
        printWarning(INVALID_FILE);
        return null;
    }
    const itrBuffer = inputBytes.slice(props.offsets.PBDKF2_ITERATIONS_BYTE_OFFSET, props.offsets.SALT_BYTE_OFFSET);
    const PBDKF2Iterations = new DataView(itrBuffer.buffer, itrBuffer.byteOffset, itrBuffer.byteLength).getUint32(0, false);
    const salt = inputBytes.slice(props.offsets.SALT_BYTE_OFFSET, props.offsets.IV_BYTE_OFFSET);
    const iv = inputBytes.slice(props.offsets.IV_BYTE_OFFSET, props.byteLength);
    return { magicBytes, versionByte, PBDKF2Iterations, salt, iv };
    
}

function compareBytes(b1: Uint8Array<ArrayBuffer>, b2: Uint8Array<ArrayBuffer>): boolean {
    if (b1.length !== b2.length) return false;
    for (let i = 0; i < b1.length; i++) {
        if (b1[i] !== b2[i]) return false;
    }
    return true;
}