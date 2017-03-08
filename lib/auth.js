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
     *  @property {string} tenant - target tenant.
     *  @property {string} appID - Application ID assigned to your app by Azure Active Directory.
     *  @property {string} redirectUri - Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
     *  @property {string} instance - Azure Active Directory Instance.Defaults to `https://login.microsoftonline.com/`.
     *  @property {string} localLoginUrl - Set this to redirect the user to a custom login page.
     *  @property {string} postLogoutRedirectUri - Redirects the user to postLogoutRedirectUri after logout. Defaults is 'redirectUri'.
     *  @property {string} cacheLocation - Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
     */

    /**
     * Initializes an auth context with the specified configuration attributes
     * if config is null context will attempt to load from storage,
     * otherwise default values will be utilized
     * @param {configuration} configuration - settings to be utilized with this instance
     * @constructor
     */
    AuthContext = function(configuration){

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
     * return the instance of the auth context object from the constructor
     */
    return AuthContext;
}());