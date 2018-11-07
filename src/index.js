import axios from 'axios';
import {generateMnemonic} from 'minterjs-wallet';
import {getPasswordToSend, getPasswordToStore, addressFromMnemonic, addressEncryptedFromMnemonic, encryptMnemonic, decryptMnemonic} from './utils';

export {getPasswordToSend, getPasswordToStore, addressFromMnemonic, addressEncryptedFromMnemonic, encryptMnemonic, decryptMnemonic};

/**
 * @param {AxiosRequestConfig} options
 * @constructor
 */
export default function MinterOrg(options) {
    const instance = axios.create(options);

    /**
     * @param {TokenData} tokenData
     */
    this.setAuthToken = function setAuthToken(tokenData) {
        instance.defaults.headers = JSON.parse(JSON.stringify(instance.defaults.headers)); // unset links from core object, will be fixed in https://github.com/axios/axios/pull/1395
        instance.defaults.headers.common.Authorization = `${tokenData.tokenType} ${tokenData.accessToken}`;
    };

    this.resetAuthToken = function resetAuthToken() {
        delete instance.defaults.headers.common.Authorization;
    };

    this.hasAuthToken = function hasAuthToken() {
        return 'Authorization' in instance.defaults.headers.common;
    };

    /**
     * @param {Object} data
     * @param {string} data.username
     * @param {string} data.password
     * @param {string} [data.mnemonic]
     * @param {string} [data.name]
     * @param {string} [data.email]
     * @param {string} [data.phone]
     * @param {string} [data.language]
     * @param {UserAvatar} [data.avatar]
     * @param {boolean} login - should make login
     * @return {Promise<User|{confirmations: Array}>}
     */
    this.register = function register(data, login) {
        // generate mnemonic if not specified
        const mnemonic = data.mnemonic ? data.mnemonic : generateMnemonic();

        const passwordToStore = getPasswordToStore(data.password);
        const passwordToSend = getPasswordToSend(passwordToStore);
        const userData = {
            ...data,
            password: passwordToSend,
            mainAddress: addressEncryptedFromMnemonic(mnemonic, passwordToStore, true),
        };
        delete userData.mnemonic;

        if (login) {
            return new Promise((resolve, reject) => {
                instance.post('register', userData)
                    .then(() => {
                        this.login(data)
                            .then((authData) => {
                                resolve({
                                    ...authData,
                                    password: passwordToStore,
                                });
                            })
                            .catch(reject);
                    })
                    .catch(reject);
            });
        } else {
            return instance.post('register', userData)
                .then((response) => response.data.data);
        }
    };

    /**
     * @param username
     * @param password
     * @return {Promise<User>}
     */
    this.login = function login({username, password}) {
        const passwordToStore = getPasswordToStore(password);
        const passwordToSend = getPasswordToSend(passwordToStore);

        return instance.post('login', {
            username,
            password: passwordToSend,
        })
            .then((response) => ({
                ...response.data.data,
                password: passwordToStore,
            }));
    };

    /**
     * Requires auth
     * @return {Promise<User>}
     */
    this.getProfile = function getProfile() {
        return instance.get('profile')
            .then((response) => response.data.data);
    };

    /**
     *
     * @param profile
     * @param {string} profile.username
     * @param {string} [profile.name]
     * @param {string} [profile.email]
     * @param {string} [profile.language]
     * @return {Promise<{confirmations: Array}>}
     */
    this.updateProfile = function updateProfile(profile) {
        return instance.put('profile', profile)
            .then((response) => response.data.data);
    };
}


/**
 * @typedef {Object} TokenData
 * @property {string} tokenType
 * @property {number} expiresIn
 * @property {string} accessToken
 * @property {string} refreshToken
 */

/**
 * @typedef {Object} User
 * @property {string} username
 * @property {string} name
 * @property {string} email
 * @property {string} phone
 * @property {string} language
 * @property {UserAvatar} avatar
 * @property {Address} mainAddress
 */

/**
 * @typedef {Object} UserAvatar
 * @property {string} src
 * @property {string} description
 */

/**
 * @typedef {Object} Address
 * @property {number} id
 * @property {string} address
 * @property {boolean} isMain
 * @property {boolean} isServerSecured
 * @property {string} [encrypted] - Encrypted mnemonic (if isServerSecured)
 * @property {string} [mnemonic] - Stored mnemonic (if not isServerSecured)
 */
