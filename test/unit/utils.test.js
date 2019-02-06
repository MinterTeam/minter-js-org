import crypto from 'crypto';
import aesjs from 'aes-js';
import ethUtil from 'ethereumjs-util';
import {
    aesEncrypt,
    getSha256Hex,
    prepareIV,
} from '~/src/utils';

const mnemonic = 'exercise fantasy smooth enough arrive steak demise donkey true employ jealous decide blossom bind someone';
const rawPassword = '123456';
const IV = 'pjSfpWAjdSaYpOBy';
const MINTER_IV = 'Minter seed';
const encryptedMnemonic = 'd9d480907ab1ccf89b647d5d6152edd5d098026728f3e3f0984b1538b13455579744cb967415321eff576035f8c6f75a6c999301adf1d2cbed90c2174e5ab5863aac43d54d3f34114bbb21044b2497d9d4e3d016f5b1db82d184092493507374db411acf26a93597cf644a3ad28d4759';
const encryptedMnemonicMinterIV = 'dd4ef5fc6a7b5faf123391b51dfcf7e3dc799392e848f46eafdbe82e7f725daf357c84baf30b30b4fa89e5431276cd674a494b1117a1ca213b807336a0647daeaffbff188e884e626b1b2ce005826f7b7fa9af8024498928426441ca83c1be666cbba64274ee8d0a4f6458a2d472aaa3';

test('sha256 ethUtil length', () => {
    const shaPasswordBuffer = ethUtil.sha256(rawPassword);
    const shaPasswordHex = shaPasswordBuffer.toString('hex');
    const shaPasswordBytes = aesjs.utils.hex.toBytes(shaPasswordHex);
    expect(shaPasswordBuffer).toHaveLength(32);
    expect(shaPasswordBytes).toHaveLength(32);
    expect(shaPasswordHex).toEqual(ethUtil.setLengthLeft(shaPasswordBuffer, 32).toString('hex'));
});

test('sha256 ethUtil equal to crypto', () => {
    const passShaEth = ethUtil.sha256(rawPassword).toString('hex');
    const passShaCrypto = crypto.createHash('sha256').update(rawPassword, 'utf8').digest('hex');
    expect(passShaEth).toEqual(passShaCrypto);
});

test('to bytes aes-js', () => {
    const shaPasswordBuffer = ethUtil.sha256(rawPassword);
    const shaPasswordHex = shaPasswordBuffer.toString('hex');
    const passwordBytes = aesjs.utils.hex.toBytes(shaPasswordHex);
    expect(passwordBytes).toEqual(shaPasswordBuffer.toJSON().data);
});

test('prepare iv', () => {
    const bytesIV = prepareIV(MINTER_IV);
    expect(aesjs.utils.hex.fromBytes(bytesIV)).toEqual('4d696e74657220736565640000000000');
});

test('aes encryption', () => {
    const hexPassword = getSha256Hex(rawPassword);
    const bytesIV = prepareIV(IV);
    const result = aesEncrypt(mnemonic, hexPassword, bytesIV);
    expect(result).toEqual(encryptedMnemonic);
});

test('aes encryption, minter iv', () => {
    const hexPassword = getSha256Hex(rawPassword);
    const bytesIV = prepareIV(MINTER_IV);
    const result = aesEncrypt(mnemonic, hexPassword, bytesIV);

    const textBytes = aesjs.utils.utf8.toBytes(mnemonic);
    const keyBytes = aesjs.utils.hex.toBytes(hexPassword);
    // eslint-disable-next-line new-cap
    const aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, bytesIV);
    const encryptedBytes = aesCbc.encrypt(aesjs.padding.pkcs7.pad(textBytes));
    const resultBySteps = aesjs.utils.hex.fromBytes(encryptedBytes);

    expect(result).toEqual(resultBySteps);
    expect(result).toEqual(encryptedMnemonicMinterIV);
});
