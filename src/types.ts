/**
 * Byte offsets for each component of the encryption header
 */
export type EncryptionHeaderOffsets = Readonly<{
    MAGIC_BYTE_OFFSET: number;
    VERSION_BYTE_OFFSET: number;
    PBDKF2_ITERATIONS_BYTE_OFFSET: number;
    SALT_BYTE_OFFSET: number;
    IV_BYTE_OFFSET: number;
}>

/**
 * Necessary information and metadata about the encryption header. Single source of truth for 
 * encryption and decryption methods to read from.
 */
export type EncryptionHeaderProperties = Readonly<{
    byteLength: number;
    magicBytes: Uint8Array<ArrayBuffer>;
    offsets: EncryptionHeaderOffsets;
    PBDKF2hashIterations: number;
    versionByteList: Uint8Array<ArrayBuffer>;
}>

/**
 * A typed representation of an encryption header
 */
export type EncryptionHeader = Readonly<{
    magicBytes: Uint8Array<ArrayBuffer>;
    versionByte: number;
    PBDKF2Iterations: number;
    salt: Uint8Array<ArrayBuffer>;
    iv: Uint8Array<ArrayBuffer>;
}>