#!/usr/bin/env node
import type { EncryptionHeaderProperties } from "./types.ts";
import { HEADER_PROPERTIES } from "./headerProperties.ts";
import { readInputFileBytes, writeOutputFile } from "./util.ts";
import { askOverwritePermission, getPassphrase, printSuccess } from "./cli.ts";
import encrypt from "./encrypt.ts";
import decrypt from "./decrypt.ts";

import fs from "node:fs"
import path from "node:path";
import { exit } from "node:process";

import { Command } from "commander";


const program = new Command();

program
    .name("file-encrypt")
    .description("Encrypt and decrypt files with passphrases")
    .version("1.0.0");

program
    .command("encrypt <inputFile> <outputFile>")
    .description("Encrypt file at path `inputFile`, and output at path `outputFile`.")
    .action(async (inputFile, outputFile) => {
        runEncryption(inputFile, outputFile, HEADER_PROPERTIES);
    });

program
    .command("decrypt <inputFile> <outputFile>")
    .description("Decrypt a file at `inputPath`, and output at path `outputFile`.")
    .action(async (inputFile, outputFile) => {
        runDecryption(inputFile, outputFile, HEADER_PROPERTIES);
    });

program.parseAsync();

async function runEncryption(inputPath: string, outputPath: string, props: EncryptionHeaderProperties): Promise<void> {
    const inputFileBytes: Uint8Array<ArrayBuffer> = await readInputFileBytes(inputPath);
    const passphrase: string = getPassphrase(true);
    const encryptedData: Uint8Array<ArrayBuffer> = await encrypt(inputFileBytes, passphrase, props);
    const resolvedOutPath = path.resolve(outputPath);
    if (fs.existsSync(resolvedOutPath) && !askOverwritePermission(resolvedOutPath)) exit();
    writeOutputFile(encryptedData, resolvedOutPath);
    printSuccess("File encrypted successfully.");
}

async function runDecryption(inputPath: string, outputPath: string, props: EncryptionHeaderProperties): Promise<void> {
    const inputFileBytes: Uint8Array<ArrayBuffer> = await readInputFileBytes(inputPath);
    const passphrase: string = getPassphrase(false);
    const decryptedData: Uint8Array<ArrayBuffer> = await decrypt(inputFileBytes, passphrase, props);
    const resolvedOutPath = path.resolve(outputPath);
    if (fs.existsSync(resolvedOutPath) && !askOverwritePermission(resolvedOutPath)) exit();
    writeOutputFile(decryptedData, resolvedOutPath);
    printSuccess("File decrypted successfully.");
}