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

/**
 * @callback authorizeCallback
 * @param {string} error - contains error description if error state, null if no error present
 * @param {string} token - authorization token resulting from renew or login request, null if error
 */

/**
 * Configuration options for Authentication Context.
 *  @class configuration
 *  @property {string} azureTenant - target tenant.
 *  @property {string} azureAppID - Application ID assigned to your app by Azure Active Directory.
 *  @property {string} azureLoginRedirectUri - Endpoint at which you expect to receive tokens.Defaults to `window.location.href`.
 *  @property {string} azureInstance - Azure Active Directory Instance.Defaults to `https://login.microsoftonline.com/`.
 *  @property {string} authorizationServiceLoginUri - Endpoint to which the azure provided authentication token will be sent to acquire an authorization token
 *  @property {string} authorizationServiceRenewUri - Endpoint to which the azure provided authentication token will be sent to renew an authorization token
 *  @property {String[]} authorizationContexts - authorization contextual permission to load into the authorization token.
 *  @property {string} cacheLocation - Sets browser storage to either 'localStorage' or sessionStorage'. Defaults to 'sessionStorage'.
 *  @property {string} [azureLogoutRedirectUri] - Redirects the user to postLogoutRedirectUri after logout. Defaults is 'redirectUri'.
 *  @property {boolean} [logoutGlobalAzure] - Optional on logout should azure global login additionaly be terminated
 */

/**
 * @class AuthContext
 */
var AuthContext = (function(){
    
    /**
     * Initializes an auth context with the specified configuration attributes
     * if config is null context will attempt to load from storage,
     * otherwise default values will be utilized
     * @param {configuration} config - settings to be utilized with this instance
     * @constructor
     */
    AuthContext = function(config){

        /**
         * Enum for request type
         * @enum {string}
         */
        this.REQUEST_TYPE = {
            LOGIN: 'LOGIN',
            RENEW_TOKEN: 'RENEW',
            UNKNOWN: 'UNKNOWN'
        };

        /**
         * Enum for storage constants
         * @enum {string}
         */
        this.CONSTANTS = {
            ACCESS_TOKEN: 'auth_token',
            EXPIRES_IN: 'expires_in',
            USER_OBJ: 'user_object',
            ERROR_DESCRIPTION: 'error_description',
            SESSION_STATE: 'session_state',
            ID_TOKEN: 'id_token',
            STORAGE: {
                STATE_LOGIN: 'azure.state.login',
                NONCE_IDTOKEN: 'azure.nonce.idtoken',
                LOGIN_REQUEST: 'azure.login.request',
                ERROR: 'azure.error',
                ERROR_DESCRIPTION: 'azure.error.description',
                USER_TOKEN : 'user_token',
                USER_OBJ: 'user_obj',
                TOKEN_EXPIRATION: 'token_exp',
            }
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
        this.config = config || {};
        this._actionInProgress = false;

        //verify tenant and app id configuration
        if(!this.config.azureTenant || this.config.azureTenant.trim().length == 0){
            throw new Error("Tenant must be defined");
        }

        if(!this.config.azureAppID || this.config.azureAppID.trim().length == 0){
            throw new Error("An App Id must be supplied");
        }

        if(!this.config.authorizationServiceLoginUri){
            throw new Error("Authorization Service login endpoint is required");
        }

        if(!this.config.authorizationServiceRenewUri){
            throw new Error("Authorization Service renew endpoint is required");
        }

        if(!this.config.azureInstance || this.config.azureInstance.trim().length == 0){
            this.config.azureInstance = 'https://login.microsoftonline.com/';
        }

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

        //Set default cache to local storage if not set
        if(!this.config.cacheLocation || this.config.cacheLocation.trim().length == 0){
            this.config.cacheLocation = "localStorage";
        }

        if(!this.config.hasOwnProperty(logoutGlobalAzure)){
            this.config.logoutGlobalAzure = false;
        }

        //Setup storage method
        if (this.config.cacheLocation.substring(0, 5).toLowerCase() === 'local') {
            if (this._supportsLocalStorage()) {
                this._storage = localStorage;
            } else {
                throw new Error("local storage is not supported");
            }
        } else {
            if (this._supportsSessionStorage()) {
                this._storage = sessionStorage;
            } else {
                throw new Error("session storage is not supported");
            }
        }
    };


    // #PUBLIC SECTION
    /**
     * Tie into the window/ azure authentication cycle to acquire a final the final authorization token
     * @param {authorizeCallback} callback
     */
    AuthContext.prototype.authorize = function(callback){

        if(!callback || typeof callback !== 'function'){
            throw new Error("A callback function must be supplied due to the async nature of this function");
        }

        var hash = this._getHash();
        var obj = this._deserialize(hash);

        //determine if this is a response from azure based on the window.location.hash contents
        //if so begin the process of getting the returned authentication token and calling the authorization service
        if(this._isCallback(obj)){
            var obj = this._getRequestInfo(obj);

            //determine if there was an error in the azure pipeline
            if(obj.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION)){
                //error present set the values to storage for later retrieval
                this._store(this.CONSTANTS.STORAGE.ERROR, obj['error']);
                this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, obj[this.CONSTANTS.ERROR_DESCRIPTION]);

                if(obj.requestInfo.requestType === this.REQUEST_TYPE.LOGIN){
                    this._actionInProgress = false;
                }
            }else {
                //get id token from request and begin the process of getting the authorization token
                if(obj.requestInfo.stateMatch){
                    var azureToken = obj[this.CONSTANTS.ID_TOKEN];

                    //make sure token was passed
                    if(!azureToken){
                        callback('authorization not available', false);
                    }

                    //setup call to authorization service
                    var handler = this._handleServiceResponse.bind(this);

                    var xhr = new XMLHttpRequest();
                    xhr.onreadystatechange = function(){
                        if(xhr.readyState === XMLHttpRequest.DONE){
                            handler(xhr.status, xhr.statusText, xhr.responseText, callback);
                        }
                    };

                    xhr.open("POST", this.config.authorizationServiceLoginUri , true);
                    xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8");
                    xhr.send(JSON.stringify({authorization_token: azureToken, contexts: this.config.authorizationContexts}));

                }else{
                    this._store(this.CONSTANTS.STORAGE.ERROR, 'Invalid State');
                    this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, 'Invalid State, state: ' + obj.requestInfo.stateResponse);

                    if(obj.requestInfo.requestType === this.REQUEST_TYPE.LOGIN){
                        this._actionInProgress = false;
                    }
                }
            }
        }
    };

    /**
     * Renews an existing authorization token that has expired.
     * @param {authorizeCallback} callback
     */
    AuthContext.prototype.renew = function(callback){

        if(!callback || typeof callback !== 'function'){
            throw new Error("A callback function must be supplied due to the async nature of this function");
        }

        this._actionInProgress = true;

        //make sure token was passed
        var token = this._get(this.CONSTANTS.USER_TOKEN);

        //make sure callback was provided
        if (!callback || typeof callback !== 'function') {
            throw new Error('callback is not a function');
        }

        //make sure token was passed
        if(!token){
            callback('authorization token not found', null)
        }

        if(!this._config.urls.renew){
            callback('unknown/invalid authorization url',null)
        }

        var handler = this._handleServiceResponse.bind(this);

        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function(){
            if(xhr.readyState === XMLHttpRequest.DONE){
                handler(xhr.status, xhr.statusText, xhr.responseText, callback);
            }
        };

        xhr.open("POST", this.config.authorizationServiceRenewUri , true);
        xhr.setRequestHeader("Content-Type", "application/json; charset=utf-8");


        xhr.send(JSON.stringify({authorization_token: token}));
    };

    /**
     * Initiates the login process
     * @param {string} startPage - [Optional] URL of starting page, current window.location default
     */
    AuthContext.prototype.login = function(startPage){
        if(this._actionInProgress){
            //STOP : we dot want to do this more than needed,
            return;
        }

        var expectedState = this._uuid();
        this.config.state = expectedState;
        this._idTokenNonce = this._uuid();
        this._store(this.CONSTANTS.STORAGE.LOGIN_REQUEST, startPage || window.location.href);
        this._store(this.CONSTANTS.STORAGE.STATE_LOGIN, expectedState);
        this._store(this.CONSTANTS.STORAGE.NONCE_IDTOKEN, this._idTokenNonce);
        this._store(this.CONSTANTS.STORAGE.ERROR, '');
        this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION, '');
        var urlNavigate = this._generateAzureLoginURL('id_token', null) + '&nonce=' + encodeURIComponent(this._idTokenNonce);
        this._actionInProgress = true;

        this._prompt(urlNavigate);
    };

    /**
     * Provides indication if there is currently an action (login or renew) in progress
     * @returns {boolean}
     */
    AuthContext.prototype.isActionInProgress = function(){
        try{
            return this._actionInProgress;
        }catch(e){
            return false;  // All hell has broken loose just return false
        }
    };


    /**
     * Extracts the User token to the caller
     * @returns {string}
     */
    AuthContext.prototype.getToken = function(){
        return this._get(this.CONSTANTS.STORAGE.USER_TOKEN);
    };

    /**
     * Extracts the user information to the caller
     * @returns {object}
     */
    AuthContext.prototype.getUserInformation = function(){
        if(this._config.storeToken) {
            return JSON.parse(this._get(this.CONSTANTS.STORAGE.USER_OBJ));
        }else{
            return null;
        }
    };

    AuthContext.prototype.isTokenExpired = function(){
        return (parseInt(this._get(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION)) - Math.floor(Date.now() / 1000)) > 0
    };

    AuthContext.prototype.getTokenExpirationInSeconds = function(){
        return (parseInt(this._get(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION)) - Math.floor(Date.now() / 1000))
    };

    /**
     * Logs the users out and destroys all persisted data
     * @param {authorizeCallback} callback
     */
    AuthContext.prototype.logout = function(callback){
        //purge all known values in storage
        for(var key in this.CONSTANTS.STORAGE){
            if(this.CONSTANTS.STORAGE.hasOwnProperty(key)){
                this._purge(this.STORAGE['key']);
            }
        }

        // if configured logout of the global azure session
        if(this.config.logoutGlobalAzure){
            this.promptUser(this._generateAzureLogoutURL());
        }

        if(callback && typeof callback === 'function'){
            callback(null, null);
        }
    };

    // #PRIVATE SECTION

    /**
     * clean up window.location.hash
     * @returns {string}
     * @private
     */
    AuthContext.prototype._getHash = function(){
        var hash = window.location.hash;
        if (hash.indexOf('#/') > -1) {
            hash = hash.substring(hash.indexOf('#/') + 2);
        } else if (hash.indexOf('#') > -1) {
            hash = hash.substring(1);
        }
        return hash;
    };


    /**
     * begin to eval the request data,
     * @param obj
     * @private
     */
    AuthContext.prototype._getRequestInfo = function(obj){
        var requestInfo = {
            valid: false,
            stateMatch: false,
            stateResponse: '',
            requestType: this.REQUEST_TYPE.UNKNOWN
        };
        if (obj) {
            obj['requestInfo'] = requestInfo;
            if (this._isCallback(obj)) {

                obj.requestInfo.valid = true;

                // which call
                var stateResponse = '';
                if (obj.hasOwnProperty('state')) {
                    stateResponse = obj.state;
                } else {
                    return obj;
                }

                obj.requestInfo.stateResponse = stateResponse;

                // make sure the request is in relation to this context instance's request
                // who knows how this would not be true given the singleton but just in case, possibly more than one window/tab open,
                // or maybe someone is trying a hack.
                //
                if (obj.requestInfo.stateResponse === this._get(this.CONSTANTS.STORAGE.STATE_LOGIN)) {
                    obj.requestInfo.requestType = this.REQUEST_TYPE.LOGIN;
                    obj.requestInfo.stateMatch = true;
                    return obj;
                }
            }
        }
        return obj;
    };

    /**
     * Determines if this is a response from azure based on the window.location.hash contents
     * @param {object} obj
     * @returns {boolean}
     * @private
     */
    AuthContext.prototype._isCallback = function(obj){
        return (obj.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION) ||
        obj.hasOwnProperty(this.CONSTANTS.ACCESS_TOKEN) ||
        obj.hasOwnProperty(this.CONSTANTS.ID_TOKEN));
    };

    /**
     * deserialize an object from querystring formatted data
     * @param {string} data
     * @returns {object}
     * @private
     */
    AuthContext.prototype._deserialize = function (data) {
        var match,
            pl = /\+/g,  // Regex for replacing addition symbol with a space
            search = /([^&=]+)=([^&]*)/g,
            decode = function (s) {
                return decodeURIComponent(s.replace(pl, ' '));
            },
            obj = {};
        match = search.exec(data);
        while (match) {
            obj[decode(match[1])] = decode(match[2]);
            match = search.exec(data);
        }
        return obj;
    };

    /**
     * Prompts the user to login via redirect
     *
     * @param url
     * @private
     */
    AuthContext.prototype._prompt = function(url){
        if (url) {
            window.location.replace(url);
        } else{
            throw new Error('Invalid url');
        }
    };

    /**
     *  Generates the Azure Login redirect URL based on configured settings and context
     * @param responseType
     * @param resource
     * @returns {string}
     * @private
     */
    AuthContext.prototype._generateAzureLoginURL = function (responseType, params ,resource) {

        var buffer = [];
        buffer.push('?response_type=' + responseType);
        buffer.push('client_id=' + encodeURIComponent(params.azureAppID));
        if (resource) {
            buffer.push('resource=' + encodeURIComponent(resource));
        }

        buffer.push('redirect_uri=' + encodeURIComponent(params.azureLoginRedirectUri));
        buffer.push('state=' + encodeURIComponent(params.state));

        if (params.hasOwnProperty('slice')) {
            buffer.push('slice=' + encodeURIComponent(params.slice));
        }

        if (params.hasOwnProperty('additionalQueryParameter')) {
            buffer.push(params.additionalQueryParameter);
        }

        var azureRequestId = params.azureRequestId ? params.azureRequestId : this._guid();
        buffer.push('client-request-id=' + encodeURIComponent(azureRequestId));

        var qs = buffer.join('&');


        var urlNavigate = this.config.azureInstance + this.config.azureTenant + '/oauth2/authorize' + qs;

        return urlNavigate;
    };

    /**
     * Generates the Azure Logout redirect URL based on configured settings and context
     * @returns {string}
     * @private
     */
    AuthContext.prototype._generateAzureLogoutURL = function(){
        var logout = '';
        if (this.config.azureLogoutRedirectUri) {
            logout = 'post_logout_redirect_uri=' + encodeURIComponent(this.config.azureLogoutRedirectUri);
        }
        return this.config.azureInstance + this.config.azureTenant + '/oauth2/logout?' + logout;
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
     * Handle XMLHttpRequest response from Authorization Service call
     * @param status
     * @param desc
     * @param respBody
     * @param {authorizeCallback} callback
     * @private
     */
    AuthContext.prototype._handleServiceResponse = function(status, desc, respBody, callback){
        if(status === 200 && respBody){
            var resp = JSON.parse(respBody);
            this._store(this.CONSTANTS.STORAGE.USER_TOKEN, resp.token);
            this._store(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION, resp.user.exp.toString());
            this._store(this.CONSTANTS.STORAGE.USER_OBJ, JSON.stringify(resp.user));
            callback(null, resp.token);
        }else{
            console.log("Authorization token could not be acquired, Status Code: %d, %s", status, desc);
            callback("Authorization token could not be acquired", null);
        }

        this._actionInProgress = false;
    };

    /**
     * Generates and returns a new UUID value according to UUID v4 (RFC4122) standard
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

            var decimal2Hex = function(number){
                var hex = number.toString(16);
                while (hex.length < 2) {
                    hex = '0' + hex;
                }
                return hex;
            };

            //Fill the buffer with random values using the window.crypto object's getRandomValues function
            // see Mozilla MDN  for more details:
            // < https://developer.mozilla.org/en-US/docs/Web/API/RandomSource/getRandomValues >
            cryptoObj.getRandomValues(buffer);

            //Now finagle buffer items to represent the correct values accroting to the standard
            //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
            buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
            buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
            //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
            buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
            buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.

            return decimal2Hex(buffer[0]) +
                decimal2Hex(buffer[1]) +
                decimal2Hex(buffer[2]) +
                decimal2Hex(buffer[3]) + '-' +
                decimal2Hex(buffer[4]) +
                decimal2Hex(buffer[5]) + '-' +
                decimal2Hex(buffer[6]) +
                decimal2Hex(buffer[7]) + '-' +
                decimal2Hex(buffer[8]) +
                decimal2Hex(buffer[9]) + '-' +
                decimal2Hex(buffer[10]) +
                decimal2Hex(buffer[11]) +
                decimal2Hex(buffer[12]) +
                decimal2Hex(buffer[13]) +
                decimal2Hex(buffer[14]) +
                decimal2Hex(buffer[15]);
        }
        else {

            // This client does not support window.crypto or it's random values function
            // The client browser must be very old and crappy, we should error but we have to be nice to people
            // still using old internet explorer versions even though they don't deserve it.
            // just emit a sudo random derived uuid that actually isn't that random.

            var uuid4rnd = function(x){
                var r = Math.random() * 16 | 0;
                return (x === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
            };

            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, uuid4rnd);
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