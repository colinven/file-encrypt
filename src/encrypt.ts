import type { EncryptionHeaderProperties } from "./types.ts"
import { deriveAESKeyFrom } from "./util.ts";

/**
 * Given an input `Uint8Array`, derive an AES-GCM key from the given `passphrase`, and return encrypted ciphertext 
 * prepended with a header containing `[magic bytes][version byte][pbdkf2 hash iterations][salt][iv]`
 */
export default async function encrypt(
    inputBytes: Uint8Array<ArrayBuffer>, passphrase: string, props: EncryptionHeaderProperties
): Promise<Uint8Array<ArrayBuffer>> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const derivedAESKey = await deriveAESKeyFrom(passphrase, salt, props.PBDKF2hashIterations, ["encrypt"]);
    const encryptionHeader = buildEncryptionHeader(props, salt, iv);
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
            additionalData: encryptionHeader,
        },
        derivedAESKey,
        inputBytes
    );
    const blob = new Uint8Array(encryptionHeader.byteLength + ciphertext.byteLength);
    blob.set(encryptionHeader);
    blob.set(new Uint8Array(ciphertext), props.byteLength);
    return blob;
}

/**
 * Fold magic bytes, version byte, PBDKF2 iteration count, salt, and iv into one unified encryption header
 */
function buildEncryptionHeader(
    props: EncryptionHeaderProperties, salt: Uint8Array<ArrayBuffer>, iv: Uint8Array<ArrayBuffer>
): Uint8Array<ArrayBuffer> {
    const header = new Uint8Array(props.byteLength);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    header.set(props.magicBytes, props.offsets.MAGIC_BYTE_OFFSET);
    view.setUint8(props.offsets.VERSION_BYTE_OFFSET, props.versionByteList[props.versionByteList.length-1]);
    view.setUint32(props.offsets.PBDKF2_ITERATIONS_BYTE_OFFSET, props.PBDKF2hashIterations, false);
    header.set(salt, props.offsets.SALT_BYTE_OFFSET);
    header.set(iv, props.offsets.IV_BYTE_OFFSET);
    return header;
}
