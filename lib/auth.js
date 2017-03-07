/**
 * @name Auth.js
 * @version 1.0.0
 * @author Karl Moad <github.com/karlmoad>
 *
 *  A javascript class library that encapsulates the implementation of Single Page Application
 *  Authentication and Authorization processes with Active Directory and authorization sources.  Azure
 *  Active Directory is configured to include an application for use by this library.  Client application
 *  then first authenticate to the Azure endpoint utilizing the OAuth Implicit Grant/FLow then submit the resulting
 *  token form the Azure results to the defined authorization source for a final authorization token. The Authorization
 *  token will be retained in browser storage for later use
 *
 *  @summary use Azure Active Directory to get an authentication token and exchange it for an authorization token from the defined service
 */
var AuthContext = (function(){
    'use strict'

    AuthContext = function(config){

    };


    AuthContext.prototype._store = function(key, value){
        this._storage.setItem(key,value);
    };

    AuthContext.prototype._get = function(key){
        return this._storage.getItem(key);
    };

    AuthContext.prototype._purge = function(key){
        this._storage.removeItem(key)
    };

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

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = AuthContext;
        module.exports.inject = function (options) {
            return new AuthContext(options);
        };
    }

    return AuthContext;
}());