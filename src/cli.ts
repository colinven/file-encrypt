import readlineSync from "readline-sync";
import chalk from "chalk"

const MIN_PASSPHRASE_LENGTH = 8;
const WARNING = chalk.red.bold("!!");
const SUCCESS = chalk.green.bold("✓");

type PassphraseValidationResult = {
    ok: boolean;
    reason?: string
}

/**
 * Prompt the user for a passphrase
 * @param askConfirmation display a confirmation prompt to re-enter passphrase
 */
export function getPassphrase(askConfirmation: boolean): string {
    let input1 = "";
    let input2 = "";
    let validation: PassphraseValidationResult;
    do {
        input1 = readlineSync.question(`Enter passphrase (or ${chalk.bold("ENTER")} to cancel): `, { hideEchoBack: true }).trim();
        if (!input1) { // ^C does not register in readline-sync lib, so this gives user opportunity to exit
            process.exit();
        } 
        if (askConfirmation) {
            input2 = readlineSync.question("Confirm passphrase: ", { hideEchoBack: true }).trim();
        }
        validation = validatePassphrase(input1, input2);
        if (validation.reason) {
            printWarning(validation.reason)
        }
    } while (!validation.ok);
    return input1;
}

function validatePassphrase(p1: string, p2: string): PassphraseValidationResult {
    if (p1.length < MIN_PASSPHRASE_LENGTH) {
        return { ok: false, reason: `Passphrase must be a minimum of ${MIN_PASSPHRASE_LENGTH} non-whitespace characters.` };
    }
    if (p2 && p1 !== p2) {
        return { ok: false, reason: "Passphrases do not match." };
    }
    return { ok: true }
}

/**
 * Display a prompt asking for permission to overwrite file at `filePath` [y/n]
 * @returns `true` if user presses `Y` key, `false` if user presses `N` key, or an empty string (falsy) otherwise
 */
export function askOverwritePermission(filePath: string): string | boolean {
    return readlineSync.keyInYN(`${WARNING} File at path '${chalk.bold(filePath)}' already exists. Overwrite it? : `);
}

/**
 * Print `prompt` to the console in a formatted warning format
 */
export function printWarning(prompt: string): void {
    console.log(`${WARNING} ${prompt}`);
}

/**
 * Print `prompt` to the console in a formatted success format
 */
export function printSuccess(prompt: string): void {
    console.log(`${SUCCESS} ${prompt}`);
}
