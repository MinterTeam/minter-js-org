import axios from 'axios';
import {generateMnemonic} from 'minterjs-wallet';
import {addressEncryptedFromMnemonic, decryptMnemonic, encryptMnemonic, getPasswordToSend, getPasswordToStore} from '~/src/stash';

/**
 * @param {AxiosRequestConfig} options
 * @constructor
 */
export default function MinterOrg(options) {
    const instance = axios.create(options);
    const formDataHeaders = { 'Content-Type': 'multipart/form-data' };

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
     * POST `register`
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
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<User|{confirmations: Array}>}
     */
    this.register = function register(data, login, axiosConfig) {
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
                instance.post('register', userData, axiosConfig)
                    .then(() => {
                        this.login(data, axiosConfig)
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
            return instance.post('register', userData, axiosConfig)
                .then((response) => response.data.data);
        }
    };

    /**
     * POST `login`
     * @param username
     * @param password
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<User|{password: string}>}
     */
    this.login = function login({username, password}, axiosConfig) {
        const passwordToStore = getPasswordToStore(password);
        const passwordToSend = getPasswordToSend(passwordToStore);

        return instance.post('login', {
            username,
            password: passwordToSend,
        }, axiosConfig)
            .then((response) => ({
                ...response.data.data,
                password: passwordToStore,
            }));
    };

    /**
     * Requires auth
     * GET `profile`
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<User>}
     */
    this.getProfile = function getProfile(axiosConfig) {
        return instance.get('profile', axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     * Requires auth
     * PUT `profile`
     * @param profile
     * @param {string} [profile.username]
     * @param {string} [profile.name]
     * @param {string} [profile.email]
     * @param {string} [profile.language]
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<{confirmations: Array}>}
     */
    this.updateProfile = function updateProfile(profile, axiosConfig) {
        return instance.put('profile', profile, axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     * Update profile password and re encrypt stored mnemonics, return updated AddressList
     * Requires auth
     * GET `addresses/encrypted`
     * POST `profile/password'`
     * @param {string} oldPasswordToStore
     * @param {string} newPasswordToStore
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Array<Address>>}
     */
    this.updateProfilePassword = function updateProfilePassword(oldPasswordToStore, newPasswordToStore, axiosConfig) {
        return new Promise((resolve, reject) => {
            instance.get('addresses/encrypted?perPage=99999', axiosConfig)
                .then((response) => {
                    const addressList = response.data.data;
                    addressList.forEach((item) => {
                        const mnemonic = decryptMnemonic(item.encrypted, oldPasswordToStore);
                        item.encrypted = encryptMnemonic(mnemonic, newPasswordToStore);
                    });
                    instance
                        .post('profile/password', {
                            newPassword: getPasswordToSend(newPasswordToStore),
                            addressesEncryptedData: addressList,
                        }, axiosConfig)
                        .then(() => resolve(addressList))
                        .catch(reject);
                })
                .catch(reject);
        });
    };

    /**
     * Requires auth
     * POST `profile/avatar`
     * @param {Blob|File} avatar - image, max 0.5 MB, max 500x500
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<UserAvatar>}
     */
    this.updateProfileAvatar = function updateProfileAvatar(avatar, axiosConfig) {
        return instance
            .post('profile/avatar', makeFormData({avatar}), {
                headers: formDataHeaders,
                ...axiosConfig,
            })
            .then((response) => response.data.data);
    };

    /**
     * Requires auth
     * DELETE `profile/avatar`
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<UserAvatar>}
     */
    this.deleteProfileAvatar = function deleteProfileAvatar(axiosConfig) {
        return instance.delete('profile/avatar', axiosConfig);
    };

    /**
     * Get profile address by id without encrypted data
     * Requires auth
     * GET `addresses/{id}`
     * @param {number} id
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Address>}
     */
    this.getProfileAddress = function getProfileAddress(id, axiosConfig) {
        return instance.get(`addresses/${id}`, axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     * Get profile address by id with encrypted data
     * Requires auth
     * GET `addresses/{id}/encrypted`
     * @param {number} id
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Address>}
     */
    this.getProfileAddressEncrypted = function getProfileAddressEncrypted(id, axiosConfig) {
        return instance.get(`addresses/${id}/encrypted`, axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     * Requires auth
     * POST `addresses`
     * @param {Address} address
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise}
     */
    this.addProfileAddress = function addProfileAddress(address, axiosConfig) {
        return instance.post('addresses', address, axiosConfig);
    };

    /**
     * Requires auth
     * PUT `addresses/{id}`
     * @param {number} id
     * @param {Address} address
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise}
     */
    this.updateProfileAddress = function updateProfileAddress(id, address, axiosConfig) {
        return instance.put(`addresses/${id}`, address, axiosConfig);
    };

    /**
     * Requires auth
     * DELETE `addresses/{id}`
     * @param {number} id
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise}
     */
    this.deleteProfileAddress = function deleteProfileAddress(id, axiosConfig) {
        return instance.delete(`addresses/${id}`, axiosConfig);
    };

    /**
     * Get addresses saved in profile without encrypted data
     * Requires auth
     * GET `addresses`
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Array<Address>>}
     */
    this.getProfileAddressList = function getProfileAddressList(axiosConfig) {
        return instance.get('addresses?perPage=99999', axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     *
     * Get addresses saved in profile with encrypted data
     * Requires auth
     * GET `addresses/encrypted`
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Array<Address>>}
     */
    this.getProfileAddressListEncrypted = function getProfileAddressListEncrypted(axiosConfig) {
        return instance.get('addresses/encrypted?perPage=99999', axiosConfig)
            .then((response) => response.data.data);
    };

    /**
     * GET `info/by/addresses`
     * @param {string} address
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<UserInfo>}
     */
    this.getAddressInfo = function getAddressListInfo(address, axiosConfig) {
        return instance
            .get(`info/by/address/${address}`, {
                ...axiosConfig,
            })
            .then((response) => response.data.data);
    };

    /**
     * GET `info/by/addresses`
     * @param {Array<string>} addressList
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<Array<UserInfo>>}
     */
    this.getAddressListInfo = function getAddressListInfo(addressList, axiosConfig) {
        return instance
            .get('info/by/addresses?perPage=99999', {
                params: {
                    addresses: addressList,
                },
                ...axiosConfig,
            })
            .then((response) => response.data.data);
    };

    /**
     * GET `info/address/by/contact`
     * @param {Object} params
     * @param {string} [params.username]
     * @param {string} [params.email]
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<UserInfo>}
     */
    this.getAddressInfoByContact = function getAddressInfoByContact(params, axiosConfig) {
        return instance
            .get('info/address/by/contact', {
                params,
                ...axiosConfig,
            })
            .then((response) => response.data.data);
    };

    /**
     * GET `info/by/username/{username}`
     * @param {string} username
     * @param {AxiosRequestConfig} [axiosConfig]
     * @return {Promise<User>}
     */
    this.getUserInfo = function getAddressInfoByContact(username, axiosConfig) {
        return instance
            .get(`info/by/username/${username}`, {
                ...axiosConfig,
            })
            .then((response) => response.data.data);
    };
}


function makeFormData(data) {
    const formData = new FormData();
    Object.keys(data).forEach((key) => {
        formData.append(key, data[key]);
    });

    return formData;
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
 * @typedef {Object} UserInfo
 * @property {string} address
 * @property {User} user
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
 */
