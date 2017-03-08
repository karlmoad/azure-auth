'use strict'
/**
 * @name Auth.js
 * @version 1.0.0
 * @author Karl Moad <github.com/karlmoad>
 *
 *  A javascript class library that encapsulates the implementation of Single Page Application
 *  Authentication and Authorization processes with Active Directory and authorization sources.  Azure
 *  Active Directory is configured to include an application for use by this library.  Client application
 *  first authenticates to the Azure endpoint utilizing the OAuth Implicit Grant/FLow then submits the resulting
 *  token from the Azure results to the defined authorization service for a final authorization token. The Authorization
 *  token will be retained in browser storage for later use
 *
 *  @summary use Azure Active Directory to get an authentication token and exchange it for an authorization token from the defined service
 */
var AuthContext = (function(){

    /**
     * Configuration options for Authentication Context.
     * @class configuration
     *  @property {string} azureTenant - target tenant.
     *  @property {string} azureAppID - Application ID assigned to your app by Azure Active Directory.
     *  @property {string} azureLoginRedirectUri - Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
     *  @property {string} azureInstance - Azure Active Directory Instance.Defaults to `https://login.microsoftonline.com/`.
     *  @property {string} azureLogoutRedirectUri - Redirects the user to postLogoutRedirectUri after logout. Defaults is 'redirectUri'.
     *  @property {string} cacheLocation - Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
     */

    /**
     * Initializes an auth context with the specified configuration attributes
     * if config is null context will attempt to load from storage,
     * otherwise default values will be utilized
     * @param {configuration} config - settings to be utilized with this instance
     * @constructor
     */
    AuthContext = function(config){

        this.CONSTANTS = {
            ACCESS_TOKEN: 'auth_token',
            EXPIRES_IN: 'expires_in',
            USER_OBJ: 'user_object',
            ERROR_DESCRIPTION: 'error_description',
            SESSION_STATE: 'session_state',
            STORAGE: {
                CONFIGURATION: 'config',
                TOKEN_KEYS: 'adal.token.keys',
                ACCESS_TOKEN_KEY: 'adal.access.token.key',
                EXPIRATION_KEY: 'adal.expiration.key',
                STATE_LOGIN: 'adal.state.login',
                STATE_RENEW: 'adal.state.renew',
                NONCE_IDTOKEN: 'adal.nonce.idtoken',
                SESSION_STATE: 'adal.session.state',
                USERNAME: 'adal.username',
                IDTOKEN: 'adal.idtoken',
                ERROR: 'adal.error',
                ERROR_DESCRIPTION: 'adal.error.description',
                LOGIN_REQUEST: 'adal.login.request',
                LOGIN_ERROR: 'adal.login.error',
                RENEW_STATUS: 'adal.token.renew.status'
            },
            RESOURCE_DELIMETER: '|',
            LOADFRAME_TIMEOUT: '6000',
            TOKEN_RENEW_STATUS_CANCELED: 'Canceled',
            TOKEN_RENEW_STATUS_COMPLETED: 'Completed',
            TOKEN_RENEW_STATUS_IN_PROGRESS: 'In Progress',
            LOGGING_LEVEL: {
                ERROR: 0,
                WARN: 1,
                INFO: 2,
                VERBOSE: 3
            },
            LEVEL_STRING_MAP: {
                0: 'ERROR:',
                1: 'WARNING:',
                2: 'INFO:',
                3: 'VERBOSE:'
            },
            POPUP_WIDTH: 483,
            POPUP_HEIGHT: 600
        };

        /*
         * There can only be one highlander, if a singleton instance is already in existence
         * return it and do not proceed with context build
         */
        if (AuthContext.prototype._singleton) {
            return AuthContext.prototype._singleton;
        }
        AuthContext.prototype._singleton = this;

        // Begin to set up configuration defaults/set values and other instance needs
        this.instance = 'https://login.microsoftonline.com/';
        this.config = {};

        if (this.config.azureInstance) {
            this.instance = this.config.azureInstance;
        }

        // redirect and logout_redirect are set to current location by default
        if (!this.config.azureLoginRedirectUri) {
            // strip off query parameters or hashes from the redirect uri as AAD does not allow those.
            this.config.azureLoginRedirectUri = window.location.href.split("?")[0].split("#")[0];
        }

        if (!this.config.azureLogoutRedirectUri) {
            // strip off query parameters or hashes from the post logout redirect uri as AAD does not allow those.
            this.config.azureLogoutRedirectUri = window.location.href.split("?")[0].split("#")[0];
        }


        //serialize and store configuration






    };


    /**
     * Stores a value by key into the configured client storage medium
     * @param (string} key - key to which the storage item will be referenced
     * @param {string} value - value to store
     * @private
     */
    AuthContext.prototype._store = function(key, value){
        this._storage.setItem(key,value);
    };


    /**
     * Retrieves a value form the configured storage medium
     * @param {string} key - key to which to retrieve the value form storage for
     * @private
     */
    AuthContext.prototype._get = function(key){
        return this._storage.getItem(key);
    };

    /**
     * Removes a value from the clinet storage medium
     * @param {string} key - key of item to be removed from storage
     * @private
     */
    AuthContext.prototype._purge = function(key){
        this._storage.removeItem(key)
    };

    /**
     * Determines if the client can support local storage
     * @returns {boolean}
     * @private
     */
    AuthContext.prototype._supportsLocalStorage = function () {
        try {
            var supportsLocalStorage = 'localStorage' in window && window['localStorage'];
            if (supportsLocalStorage) {
                window.localStorage.setItem('storageTest', '');
                window.localStorage.removeItem('storageTest');
            }
            return supportsLocalStorage;
        } catch (e) {
            return false;
        }
    };

    /**
     * Determines if the clinet can support session storage
     * @returns {boolean}
     * @private
     */
    AuthContext.prototype._supportsSessionStorage = function () {
        try {
            var supportsSessionStorage = 'sessionStorage' in window && window['sessionStorage'];
            if (supportsSessionStorage) {
                window.sessionStorage.setItem('storageTest', '');
                window.sessionStorage.removeItem('storageTest');
            }
            return supportsSessionStorage;
        } catch (e) {
            return false;
        }
    };

    /**
     * Enabling library to be utilized within a require statement by node.js
     * by establishing module loader tie in
     */
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = AuthContext;
        module.exports.inject = function (options) {
            return new AuthContext(options);
        };
    }

    /**
     * Generates and returns a new UUID value according to RFC4122 standard
     * -----------------------------------------------------------------------------------------------------------------
     * RFC4122: The version 4 UUID is meant for generating UUIDs from truly-random or
     * pseudo-random numbers.
     * The algorithm is as follows:
     * Set the two most significant bits (bits 6 and 7) of the
     * clock_seq_hi_and_reserved to zero and one, respectively.
     * Set the four most significant bits (bits 12 through 15) of the
     * time_hi_and_version field to the 4-bit version number from
     * Section 4.1.3. Version4
     * Set all the other bits to randomly (or pseudo-randomly) chosen
     * values.
     * UUID                   = time-low "-" time-mid "-"time-high-and-version "-"clock-seq-reserved and low(2hexOctet)"-" node
     * time-low               = 4hexOctet
     * time-mid               = 2hexOctet
     * time-high-and-version  = 2hexOctet
     * clock-seq-and-reserved = hexOctet:
     * clock-seq-low          = hexOctet
     * node                   = 6hexOctet
     * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
     * y could be 1000, 1001, 1010, 1011 since most significant two bits needs to be 10
     * y values are 8, 9, A, B
     *
     * -----------------------------------------------------------------------------------------------------------------
     * @returns {string} uuid
     * @private
     */
    AuthContext.prototype._uuid = function () {

        var cryptoObj = window.crypto || window.msCrypto; // for IE 11
        if (cryptoObj && cryptoObj.getRandomValues) {
            var buffer = new Uint8Array(16);
            cryptoObj.getRandomValues(buffer);
            //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
            buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
            buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
            //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
            buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
            buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.
            return this._decimalToHex(buffer[0]) +
                this._decimalToHex(buffer[1]) +
                this._decimalToHex(buffer[2]) +
                this._decimalToHex(buffer[3]) + '-' +
                this._decimalToHex(buffer[4]) +
                this._decimalToHex(buffer[5]) + '-' +
                this._decimalToHex(buffer[6]) +
                this._decimalToHex(buffer[7]) + '-' +
                this._decimalToHex(buffer[8]) +
                this._decimalToHex(buffer[9]) + '-' +
                this._decimalToHex(buffer[10]) +
                this._decimalToHex(buffer[11]) +
                this._decimalToHex(buffer[12]) +
                this._decimalToHex(buffer[13]) +
                this._decimalToHex(buffer[14]) +
                this._decimalToHex(buffer[15]);
        }
        else {

            // This client does not support window.crypto or it's random values function
            // The client browser must be very shitty and we should error but we have to be nice to people
            // still using internet explorer 10 or older even though they don't deserve it.
            // just emit a sudo random (crap) derived uuid that actually isn't that random.

            var uuidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
            var hex = '0123456789abcdef';
            var r = 0;
            var uuidResponse = "";
            for (var i = 0; i < 36; i++) {
                if (uuidHolder[i] !== '-' && uuidHolder[i] !== '4') {
                    // each x and y needs to be random
                    r = Math.random() * 16 | 0;
                }
                if (uuidHolder[i] === 'x') {
                    uuidResponse += hex[r];
                } else if (uuidHolder[i] === 'y') {
                    // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                    r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                    r |= 0x8; // set pos 3 to 1 as 1???
                    uuidResponse += hex[r];
                } else {
                    uuidResponse += uuidHolder[i];
                }
            }
            return uuidResponse;
        }
    };


    /**
     * Converts decimal value to hex equivalent
     * @private
     */
    AuthContext.prototype._decimalToHex = function (number) {
        var hex = number.toString(16);
        while (hex.length < 2) {
            hex = '0' + hex;
        }
        return hex;
    }






    /**
     * return the instance of the auth context object from the constructor
     */
    return AuthContext;
}());