import {walletFromMnemonic} from 'minterjs-wallet';
import {aesDecrypt, aesEncrypt, prepareIV, getSha256Hex} from './utils';

const MINTER_IV = prepareIV('Minter seed'); // 16 bytes, should be same on all clients


/**
 * @param {string} password
 * @return {string} - password hash used to store and encrypt/decrypt mnemonics
 */
export function getPasswordToStore(password) {
    return getSha256Hex(password);
}

/**
 * @param {string} storedPasswordHash
 * @return {string} - hashed password hash used to send to the server and identificate user
 */
export function getPasswordToSend(storedPasswordHash) {
    return getSha256Hex(storedPasswordHash);
}

export function addressFromMnemonic(mnemonic, isMain = false) {
    const wallet = walletFromMnemonic(mnemonic);

    return {
        address: wallet.getAddressString(),
        mnemonic,
        isMain,
        isServerSecured: false,
    };
}

export function addressEncryptedFromMnemonic(mnemonic, password, isMain = false) {
    const wallet = walletFromMnemonic(mnemonic);

    return {
        address: wallet.getAddressString(),
        encrypted: encryptMnemonic(mnemonic, password),
        isMain,
        isServerSecured: true,
    };
}

export function encryptMnemonic(mnemonic, password) {
    return aesEncrypt(mnemonic, password, MINTER_IV);
}

export function decryptMnemonic(encrypted, password) {
    return aesDecrypt(encrypted, password, MINTER_IV);
}
