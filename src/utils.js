import {sha256} from 'ethereumjs-util/dist/hash';
import {toBuffer, setLengthRight} from 'ethereumjs-util/dist/bytes';
import aesjs from 'aes-js';


/**
 * @param {string} text - plain text
 * @param {string} key - hex encryption key (32 bytes length)
 * @param {Array|Buffer|Uint8Array} IV - initialization vector
 * @return {string} - encrypted hex string
 */
export function aesEncrypt(text, key, IV) {
    const textBytes = aesjs.utils.utf8.toBytes(text);
    const keyBytes = aesjs.utils.hex.toBytes(key);
    // eslint-disable-next-line new-cap
    const aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, IV);
    const encryptedBytes = aesCbc.encrypt(aesjs.padding.pkcs7.pad(textBytes));
    return aesjs.utils.hex.fromBytes(encryptedBytes);
}

/**
 * @param {string} encrypted - hex string
 * @param {string} key - hex decryption key (32 bytes length)
 * @param {Array|Buffer|Uint8Array} IV - initialization vector
 * @return {string} - decrypted plain text
 */
export function aesDecrypt(encrypted, key, IV) {
    const encryptedBytes = aesjs.utils.hex.toBytes(encrypted);
    const keyBytes = aesjs.utils.hex.toBytes(key);
    // eslint-disable-next-line new-cap
    const aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, IV);
    const textBytes = aesjs.padding.pkcs7.strip(aesCbc.decrypt(encryptedBytes));
    return aesjs.utils.utf8.fromBytes(textBytes);
}

/**
 * @param {string|Buffer} text - plain text
 * @return {Buffer|Array}
 */
export function prepareIV(text) {
    if (typeof text === 'string') {
        text = Buffer.from(text, 'utf-8');
    }
    return setLengthRight(toBuffer(text), 16);
}

export function getSha256Hex(value) {
    if (typeof value === 'string') {
        value = Buffer.from(value, 'utf-8');
    }
    return sha256(value).toString('hex');
}
