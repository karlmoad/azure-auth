"use strict";var AuthContext=function(){return AuthContext=function(t){if(this.REQUEST_TYPE={LOGIN:"LOGIN",RENEW_TOKEN:"RENEW",UNKNOWN:"UNKNOWN"},this.CONSTANTS={ACCESS_TOKEN:"auth_token",EXPIRES_IN:"expires_in",USER_OBJ:"user_object",ERROR_DESCRIPTION:"error_description",SESSION_STATE:"session_state",ID_TOKEN:"id_token",STORAGE:{STATE_LOGIN:"azure.state.login",NONCE_IDTOKEN:"azure.nonce.idtoken",LOGIN_REQUEST:"azure.login.request",ERROR:"azure.error",ERROR_DESCRIPTION:"azure.error.description",USER_TOKEN:"user_token",USER_OBJ:"user_obj",TOKEN_EXPIRATION:"token_exp"}},AuthContext.prototype._singleton)return AuthContext.prototype._singleton;if(AuthContext.prototype._singleton=this,this.config=t||{},this._actionInProgress=!1,!this.config.azureTenant||0==this.config.azureTenant.trim().length)throw new Error("Tenant must be defined");if(!this.config.azureAppID||0==this.config.azureAppID.trim().length)throw new Error("An App Id must be supplied");if(!this.config.authorizationServiceLoginUri)throw new Error("Authorization Service login endpoint is required");if(!this.config.authorizationServiceRenewUri)throw new Error("Authorization Service renew endpoint is required");if(this.config.azureInstance&&0!=this.config.azureInstance.trim().length||(this.config.azureInstance="https://login.microsoftonline.com/"),this.config.azureInstance&&(this.instance=this.config.azureInstance),this.config.azureLoginRedirectUri||(this.config.azureLoginRedirectUri=window.location.href.split("?")[0].split("#")[0]),this.config.azureLogoutRedirectUri||(this.config.azureLogoutRedirectUri=window.location.href.split("?")[0].split("#")[0]),this.config.cacheLocation&&0!=this.config.cacheLocation.trim().length||(this.config.cacheLocation="localStorage"),"local"===this.config.cacheLocation.substring(0,5).toLowerCase()){if(!this._supportsLocalStorage())throw new Error("local storage is not supported");this._storage=localStorage}else{if(!this._supportsSessionStorage())throw new Error("session storage is not supported");this._storage=sessionStorage}},AuthContext.prototype.authorize=function(t){var e=this._getHash(),o=this._deserialize(e);if(this._isCallback(o)){var o=this._getRequestInfo(o);if(o.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION))this._store(this.CONSTANTS.STORAGE.ERROR,o.error),this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION,o[this.CONSTANTS.ERROR_DESCRIPTION]),o.requestInfo.requestType===this.REQUEST_TYPE.LOGIN&&(this._actionInProgress=!1);else if(o.requestInfo.stateMatch){var n=o[this.CONSTANTS.ID_TOKEN];n||t("authorization not available",!1);var r=this._handleServiceResponse.bind(this),i=new XMLHttpRequest;i.onreadystatechange=function(){i.readyState===XMLHttpRequest.DONE&&r(i.status,i.statusText,i.responseText,t)},i.open("POST",this.config.authorizationServiceLoginUri,!0),i.setRequestHeader("Content-Type","application/json; charset=utf-8"),i.send(JSON.stringify({authorization_token:n}))}else this._store(this.CONSTANTS.STORAGE.ERROR,"Invalid State"),this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION,"Invalid State, state: "+o.requestInfo.stateResponse),o.requestInfo.requestType===this.REQUEST_TYPE.LOGIN&&(this._actionInProgress=!1)}},AuthContext.prototype.renew=function(t){var e=this._get(this.CONSTANTS.USER_TOKEN);if(!t||"function"!=typeof t)throw new Error("callback is not a function");e||t("authorization token not found",null),this._config.urls.renew||t("unknown/invalid authorization url",null);var o=this._handleServiceResponse.bind(this),n=new XMLHttpRequest;n.onreadystatechange=function(){n.readyState===XMLHttpRequest.DONE&&o(n.status,n.statusText,n.responseText,t)},n.open("POST",this.config.authorizationServiceRenewUri,!0),n.setRequestHeader("Content-Type","application/json; charset=utf-8"),n.send(JSON.stringify({authorization_token:e}))},AuthContext.prototype.login=function(t){if(!this._actionInProgress){var e=this._uuid();this.config.state=e,this._idTokenNonce=this._uuid(),this._store(this.CONSTANTS.STORAGE.LOGIN_REQUEST,t||window.location.href),this._store(this.CONSTANTS.STORAGE.STATE_LOGIN,e),this._store(this.CONSTANTS.STORAGE.NONCE_IDTOKEN,this._idTokenNonce),this._store(this.CONSTANTS.STORAGE.ERROR,""),this._store(this.CONSTANTS.STORAGE.ERROR_DESCRIPTION,"");var o=this._generateAzureLoginURL("id_token",null)+"&nonce="+encodeURIComponent(this._idTokenNonce);this._actionInProgress=!0,this._prompt(o)}},AuthContext.prototype.isActionInProgress=function(){try{return this._actionInProgress}catch(t){return!1}},AuthContext.prototype.getToken=function(){return this._get(this.CONSTANTS.STORAGE.USER_TOKEN)},AuthContext.prototype.getUserInformation=function(){return this._config.storeToken?JSON.parse(this._get(this.CONSTANTS.STORAGE.USER_OBJ)):null},AuthContext.prototype.isTokenExpired=function(){return parseInt(this._get(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION))-Math.floor(Date.now()/1e3)>0},AuthContext.prototype.getTokenExpirationInSeconds=function(){return parseInt(this._get(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION))-Math.floor(Date.now()/1e3)},AuthContext.prototype.logout=function(){for(var t in this.CONSTANTS.STORAGE)this.CONSTANTS.STORAGE.hasOwnProperty(t)&&this._purge(this.STORAGE.key)},AuthContext.prototype._getHash=function(){var t=window.location.hash;return t.indexOf("#/")>-1?t=t.substring(t.indexOf("#/")+2):t.indexOf("#")>-1&&(t=t.substring(1)),t},AuthContext.prototype._getRequestInfo=function(t){var e={valid:!1,stateMatch:!1,stateResponse:"",requestType:this.REQUEST_TYPE.UNKNOWN};if(t&&(t.requestInfo=e,this._isCallback(t))){t.requestInfo.valid=!0;var o="";if(!t.hasOwnProperty("state"))return t;if(o=t.state,t.requestInfo.stateResponse=o,t.requestInfo.stateResponse===this._get(this.CONSTANTS.STORAGE.STATE_LOGIN))return t.requestInfo.requestType=this.REQUEST_TYPE.LOGIN,t.requestInfo.stateMatch=!0,t}return t},AuthContext.prototype._isCallback=function(t){return t.hasOwnProperty(this.CONSTANTS.ERROR_DESCRIPTION)||t.hasOwnProperty(this.CONSTANTS.ACCESS_TOKEN)||t.hasOwnProperty(this.CONSTANTS.ID_TOKEN)},AuthContext.prototype._deserialize=function(t){var e,o=/\+/g,n=/([^&=]+)=([^&]*)/g,r=function(t){return decodeURIComponent(t.replace(o," "))},i={};for(e=n.exec(t);e;)i[r(e[1])]=r(e[2]),e=n.exec(t);return i},AuthContext.prototype._prompt=function(t){if(!t)throw new Error("Invalid url");window.location.replace(t)},AuthContext.prototype._generateAzureLoginURL=function(t,e,o){var n=[];n.push("?response_type="+t),n.push("client_id="+encodeURIComponent(e.azureAppID)),o&&n.push("resource="+encodeURIComponent(o)),n.push("redirect_uri="+encodeURIComponent(e.azureLoginRedirectUri)),n.push("state="+encodeURIComponent(e.state)),e.hasOwnProperty("slice")&&n.push("slice="+encodeURIComponent(e.slice)),e.hasOwnProperty("additionalQueryParameter")&&n.push(e.additionalQueryParameter);var r=e.azureRequestId?e.azureRequestId:this._guid();n.push("client-request-id="+encodeURIComponent(r));var i=n.join("&"),s=this.config.azureInstance+this.config.azureTenant+"/oauth2/authorize"+i;return s},AuthContext.prototype._store=function(t,e){this._storage.setItem(t,e)},AuthContext.prototype._get=function(t){return this._storage.getItem(t)},AuthContext.prototype._purge=function(t){this._storage.removeItem(t)},AuthContext.prototype._supportsLocalStorage=function(){try{var t="localStorage"in window&&window.localStorage;return t&&(window.localStorage.setItem("storageTest",""),window.localStorage.removeItem("storageTest")),t}catch(t){return!1}},AuthContext.prototype._supportsSessionStorage=function(){try{var t="sessionStorage"in window&&window.sessionStorage;return t&&(window.sessionStorage.setItem("storageTest",""),window.sessionStorage.removeItem("storageTest")),t}catch(t){return!1}},AuthContext.prototype._handleServiceResponse=function(t,e,o,n){if(200===t&&o){var r=JSON.parse(o);this._store(this.CONSTANTS.STORAGE.USER_TOKEN,r.token),this._store(this.CONSTANTS.STORAGE.TOKEN_EXPIRATION,r.user.exp.toString()),this._store(this.CONSTANTS.STORAGE.USER_OBJ,JSON.stringify(r.user)),n(null,!0)}else console.log("Authorization token could not be acquired, Status Code: %d, %s",t,e),n("Authorization token could not be acquired",null)},AuthContext.prototype._uuid=function(){var t=window.crypto||window.msCrypto;if(t&&t.getRandomValues){var e=new Uint8Array(16),o=function(t){for(var e=t.toString(16);e.length<2;)e="0"+e;return e};return t.getRandomValues(e),e[6]|=64,e[6]&=79,e[8]|=128,e[8]&=191,o(e[0])+o(e[1])+o(e[2])+o(e[3])+"-"+o(e[4])+o(e[5])+"-"+o(e[6])+o(e[7])+"-"+o(e[8])+o(e[9])+"-"+o(e[10])+o(e[11])+o(e[12])+o(e[13])+o(e[14])+o(e[15])}var n=function(t){var e=16*Math.random()|0;return("x"===t?e:3&e|8).toString(16)};return"xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g,n)},"undefined"!=typeof module&&module.exports&&(module.exports=AuthContext,module.exports.inject=function(t){return new AuthContext(t)}),AuthContext}();