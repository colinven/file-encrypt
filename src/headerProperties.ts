import type { EncryptionHeaderOffsets, EncryptionHeaderProperties } from "./types.ts";

const PBKDF2_HASH_ITERATIONS = 600_000;
const MAGIC_BYTES = new TextEncoder().encode("FENC");
const VERSION_BYTE_LIST = new Uint8Array([0x61]); // all valid version bytes
const HEADER_BYTE_LENGTH = 37; // [magic bytes (4), version (1), iterations (4), salt (16), iv (12)] = 37
const BYTE_OFFSETS: EncryptionHeaderOffsets = {
    MAGIC_BYTE_OFFSET: 0, // 0-3
    VERSION_BYTE_OFFSET: 4, // 4
    PBDKF2_ITERATIONS_BYTE_OFFSET: 5, // 5-8
    SALT_BYTE_OFFSET: 9, // 9-24
    IV_BYTE_OFFSET: 25 // 25-36
};
export const HEADER_PROPERTIES: EncryptionHeaderProperties = {
    byteLength: HEADER_BYTE_LENGTH,
    magicBytes: MAGIC_BYTES,
    offsets: BYTE_OFFSETS,
    PBDKF2hashIterations: PBKDF2_HASH_ITERATIONS,
    versionByteList: VERSION_BYTE_LIST
};