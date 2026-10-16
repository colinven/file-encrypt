import { describe, it, beforeEach, mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import type { EncryptionHeaderProperties } from "./types.ts";
import { HEADER_PROPERTIES } from "./headerProperties.ts";
import { readInputFileBytes, writeOutputFile } from "./util.ts";
import encrypt from "./encrypt.ts";
import decrypt from "./decrypt.ts";

// Same header layout as the real one, but with far fewer PBKDF2 rounds so the tests run fast
const TEST_PROPS: EncryptionHeaderProperties = { ...HEADER_PROPERTIES, PBDKF2hashIterations: 1_000 };
const PASSPHRASE = "correct horse battery staple";

// Error thrown by our fake process.exit(), so a test can catch it instead of the test runner quitting
class ExitCalled extends Error {
    code: number | undefined;
    constructor(code: number | undefined) {
        super(`process.exit(${code}) was called`);
        this.code = code;
    }
}

beforeEach(() => {
    mock.restoreAll();
    mock.method(process, "exit", (code?: number) => { throw new ExitCalled(code); });
    mock.method(console, "log", () => {}); // hide warning output from the code under test
});

function bytesOf(text: string): Uint8Array<ArrayBuffer> {
    return new TextEncoder().encode(text);
}

describe("encrypt", () => {
    it("writes the header in the right layout", async () => {
        const out = await encrypt(bytesOf("hello"), PASSPHRASE, TEST_PROPS);
        const view = new DataView(out.buffer, out.byteOffset, out.byteLength);

        assert.deepEqual(out.slice(0, 4), TEST_PROPS.magicBytes);
        assert.equal(out[4], TEST_PROPS.versionByteList.at(-1));
        assert.equal(view.getUint32(5, false), TEST_PROPS.PBDKF2hashIterations);
    });

    it("output is header + plaintext + 16 byte GCM tag", async () => {
        const input = bytesOf("some file contents");
        const out = await encrypt(input, PASSPHRASE, TEST_PROPS);
        assert.equal(out.length, TEST_PROPS.byteLength + input.length + 16);
    });

    it("does not leave the plaintext visible in the output", async () => {
        const input = bytesOf("a very secret message");
        const out = await encrypt(input, PASSPHRASE, TEST_PROPS);
        const body = Buffer.from(out.subarray(TEST_PROPS.byteLength));
        assert.equal(body.indexOf(Buffer.from(input)), -1);
    });

    it("uses a new salt and iv every time", async () => {
        const input = bytesOf("same input");
        const a = await encrypt(input, PASSPHRASE, TEST_PROPS);
        const b = await encrypt(input, PASSPHRASE, TEST_PROPS);
        const saltAndIv = (x: Uint8Array) => x.slice(TEST_PROPS.offsets.SALT_BYTE_OFFSET, TEST_PROPS.byteLength);
        assert.notDeepEqual(saltAndIv(a), saltAndIv(b));
        assert.notDeepEqual(a, b);
    });
});

describe("decrypt", () => {
    it("gets back the original data", async () => {
        const input = bytesOf("round trip me");
        const encrypted = await encrypt(input, PASSPHRASE, TEST_PROPS);
        const decrypted = await decrypt(encrypted, PASSPHRASE, TEST_PROPS);
        assert.deepEqual(decrypted, input);
    });

    it("works on an empty file", async () => {
        const encrypted = await encrypt(new Uint8Array(0), PASSPHRASE, TEST_PROPS);
        const decrypted = await decrypt(encrypted, PASSPHRASE, TEST_PROPS);
        assert.equal(decrypted.length, 0);
    });

    it("works on binary data", async () => {
        const input = crypto.getRandomValues(new Uint8Array(4096));
        const encrypted = await encrypt(input, PASSPHRASE, TEST_PROPS);
        const decrypted = await decrypt(encrypted, PASSPHRASE, TEST_PROPS);
        assert.deepEqual(decrypted, input);
    });

    it("reads the round count from the header, not from props", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        const otherProps = { ...TEST_PROPS, PBDKF2hashIterations: 999_999 };
        const decrypted = await decrypt(encrypted, PASSPHRASE, otherProps);
        assert.deepEqual(decrypted, bytesOf("data"));
    });

    it("exits with code 1 on a wrong passphrase", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        await assert.rejects(decrypt(encrypted, "wrong passphrase", TEST_PROPS), { code: 1 });
    });

    it("exits with code 1 if the ciphertext was changed", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        encrypted[encrypted.length - 1] ^= 0xff;
        await assert.rejects(decrypt(encrypted, PASSPHRASE, TEST_PROPS), { code: 1 });
    });

    it("exits with code 1 if the salt in the header was changed", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        encrypted[TEST_PROPS.offsets.SALT_BYTE_OFFSET] ^= 0xff;
        await assert.rejects(decrypt(encrypted, PASSPHRASE, TEST_PROPS), { code: 1 });
    });

    it("exits with code 1 if the file is shorter than the header", async () => {
        await assert.rejects(decrypt(new Uint8Array(10), PASSPHRASE, TEST_PROPS), { code: 1 });
    });

    it("exits with code 1 if the magic bytes are wrong", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        encrypted[0] = 0x00;
        await assert.rejects(decrypt(encrypted, PASSPHRASE, TEST_PROPS), { code: 1 });
    });

    it("exits with code 1 if the version byte is unknown", async () => {
        const encrypted = await encrypt(bytesOf("data"), PASSPHRASE, TEST_PROPS);
        encrypted[TEST_PROPS.offsets.VERSION_BYTE_OFFSET] = 0x00;
        await assert.rejects(decrypt(encrypted, PASSPHRASE, TEST_PROPS), { code: 1 });
    });
});

describe("file helpers", () => {
    const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "file-encrypt-test-"));

    it("writes and reads back the same bytes", async () => {
        const dir = tmpDir();
        const filePath = path.join(dir, "out.bin");
        const data = crypto.getRandomValues(new Uint8Array(256));

        writeOutputFile(data, filePath);
        assert.deepEqual(await readInputFileBytes(filePath), data);

        fs.rmSync(dir, { recursive: true });
    });

    it("exits with code 1 when the input file does not exist", async () => {
        await assert.rejects(readInputFileBytes("/no/such/file/here.txt"), { code: 1 });
    });

    it("exits with code 1 when the input path is a directory", async () => {
        const dir = tmpDir();
        await assert.rejects(readInputFileBytes(dir), { code: 1 });
        fs.rmSync(dir, { recursive: true });
    });

    it("exits with code 1 when the output path cannot be written", () => {
        assert.throws(() => writeOutputFile(new Uint8Array(1), "/no/such/dir/out.bin"), { code: 1 });
    });
});
