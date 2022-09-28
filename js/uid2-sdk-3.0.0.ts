// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

type PromiseOutcome<T> = {
    resolve: (value: T | PromiseLike<T>) => void;
    reject: (reason: any) => void;
}

enum IdentityStatus {
    ESTABLISHED = 0,
    REFRESHED = 1,
    EXPIRED = 100,
    NO_IDENTITY = -1,
    INVALID = -2,
    REFRESH_EXPIRED = -3,
    OPTOUT = -4
}

class InvalidIdentityError extends Error {
    constructor(message) {
        super(message);
        this.name = "InvalidIdentityError";
    }
}

export class UID2 {
    static get VERSION() {
        return "3.0.0";
    }
    static get COOKIE_NAME() {
        return "__uid_2";
    }
    static get DEFAULT_REFRESH_RETRY_PERIOD_MS() {
        return 5000;
    }
    static IdentityStatus = IdentityStatus;

    static setupGoogleTag() {
        if (!window.googletag) {
            window.googletag = {};
        }
        if (!window.googletag.encryptedSignalProviders) {
            window.googletag.encryptedSignalProviders = [];
        }
        window.googletag.encryptedSignalProviders.push({
            id: "uidapi.com",
            collectorFunction: () => {
                if (window.__uid2 && window.__uid2.getAdvertisingTokenAsync) {
                    return window.__uid2.getAdvertisingTokenAsync();
                } else {
                    return Promise.reject(new Error("UID2 SDK not present"));
                }
            },
        });
    }

    constructor() {

    }
        // PUBLIC METHODS

    public init(opts) {
        if (this._initCalled) {
            throw new TypeError('Calling init() more than once is not allowed');
        }

        if (typeof opts !== 'object' || opts === null) {
            throw new TypeError('opts must be an object');
        } else if (typeof opts.callback !== 'function') {
            throw new TypeError('opts.callback must be a function');
        } else if (typeof opts.refreshRetryPeriod !== 'undefined') {
            if (typeof opts.refreshRetryPeriod !== 'number')
                throw new TypeError('opts.refreshRetryPeriod must be a number');
            else if (opts.refreshRetryPeriod < 1000)
                throw new RangeError('opts.refreshRetryPeriod must be >= 1000');
        }

        this._initCalled = true;
        this._opts = opts;
        let identity = this._opts.identity ? this._opts.identity : this.loadIdentity()
        this.applyIdentity(identity);
    };
    public getAdvertisingToken() {
        return this._identity && !this.temporarilyUnavailable() ? this._identity.advertising_token : undefined;
    };
    public getAdvertisingTokenAsync() {
        if (!this.initialised()) {
            return new Promise((resolve, reject) => {
                this._promises.push({ resolve: resolve, reject: reject });
            });
        } else if (this._identity) {
            return this.temporarilyUnavailable()
                ? Promise.reject(new Error('temporarily unavailable'))
                : Promise.resolve(this._identity.advertising_token);
        } else {
            return Promise.reject(new Error('identity not available'));
        }
    };
    public isLoginRequired() {
        return this.initialised() ? !this._identity : undefined;
    };
    public disconnect() {
        this.abort();
        this.removeCookie(UID2.COOKIE_NAME);
        this._identity = undefined;
        this._lastStatus = UID2.IdentityStatus.INVALID;

        const promises = this._promises;
        this._promises = [];
        promises.forEach(p => p.reject(new Error("disconnect()")));
    };
    public abort() {
        this._initCalled = true;
        if (typeof this._refreshTimerId !== 'undefined') {
            clearTimeout(this._refreshTimerId);
            this._refreshTimerId = undefined;
        }
        if (this._refreshReq) {
            this._refreshReq.abort();
            this._refreshReq = undefined;
        }
    };

    // PRIVATE STATE

    _initCalled = false;
    _opts;
    _identity;
    _lastStatus;
    _refreshTimerId;
    _refreshReq;
    _refreshVersion;
    _promises: PromiseOutcome<string>[] = [];

    // PRIVATE METHODS

    private initialised() { return typeof this._lastStatus !== 'undefined'; }
    private temporarilyUnavailable() { return this._lastStatus === UID2.IdentityStatus.EXPIRED; }

    private getOptionOrDefault(value, defaultValue) {
        return typeof value === 'undefined' ? defaultValue : value;
    };

    private setCookie(name, identity) {
        const value = JSON.stringify(identity);
        const expires = new Date(identity.refresh_expires);
        const path = this.getOptionOrDefault(this._opts.cookiePath, "/");
        let cookie = name + "=" + encodeURIComponent(value) + " ;path=" + path + ";expires=" + expires.toUTCString();
        if (typeof this._opts.cookieDomain !== 'undefined') {
            cookie += ";domain=" + this._opts.cookieDomain;
        }
        document.cookie = cookie;
    };
    private removeCookie = (name) => {
        document.cookie = name + "=;expires=Tue, 1 Jan 1980 23:59:59 GMT";
    };
    private getCookie = (name) => {
        const docCookie = document.cookie;
        if (docCookie) {
            const payload = docCookie.split('; ').find(row => row.startsWith(name+'='));
            if (payload) {
                return decodeURIComponent(payload.split('=')[1]);
            }
        }
    };

    private updateStatus = (status, statusText) => {
        this._lastStatus = status;

        const promises = this._promises;
        this._promises = [];

        const advertisingToken = this.getAdvertisingToken();

        const result = {
            advertisingToken: advertisingToken,
            advertising_token: advertisingToken,
            status: status,
            statusText: statusText
        };
        this._opts.callback(result);

        if (advertisingToken) {
            promises.forEach(p => p.resolve(advertisingToken));
        } else {
            promises.forEach(p => p.reject(new Error(statusText)));
        }
    };
    private setValidIdentity = (identity, status, statusText) => {
        this._identity = identity;
        this.setCookie(UID2.COOKIE_NAME, identity);
        this.setRefreshTimer();
        this.updateStatus(status, statusText);
    };
    private setFailedIdentity = (status, statusText) => {
        this._identity = undefined;
        this.abort();
        this.removeCookie(UID2.COOKIE_NAME);
        this.updateStatus(status, statusText);
    };
    private checkIdentity = (identity) => {
        if (!identity.advertising_token) {
            throw new InvalidIdentityError("advertising_token is not available or is not valid");
        } else if (!identity.refresh_token) {
            throw new InvalidIdentityError("refresh_token is not available or is not valid");
        } else if (identity.refresh_response_key) {
            this._refreshVersion = 2;
        } else {
            this._refreshVersion = 1;
        }
    };
    private tryCheckIdentity = (identity) => {
        try {
            this.checkIdentity(identity);
            return true;
        } catch (err) {
            if (err instanceof InvalidIdentityError) {
                this.setFailedIdentity(UID2.IdentityStatus.INVALID, err.message);
                return false;
            } else {
                throw err;
            }
        }
    };
    private setIdentity = (identity, status, statusText) => {
        if (this.tryCheckIdentity(identity)) {
        this.setValidIdentity(identity, status, statusText);
        }
    };
    private loadIdentity = () => {
        const payload = this.getCookie(UID2.COOKIE_NAME);
        if (payload) {
            return JSON.parse(payload);
        }
    };

    private enrichIdentity = (identity, now) => {
        return {
            refresh_from: now,
            refresh_expires: now + 7 * 86400 * 1000, // 7 days
            identity_expires: now + 4 * 3600 * 1000, // 4 hours
            ...identity,
        };
    };
    private applyIdentity = (identity) => {
        if (!identity) {
            this.setFailedIdentity(UID2.IdentityStatus.NO_IDENTITY, "Identity not available");
            return;
        }

        if (!this.tryCheckIdentity(identity)) {
            // failed identity already set
            return;
        }

        const now = Date.now();
        identity = this.enrichIdentity(identity, now);
        if (identity.refresh_expires < now) {
            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Identity expired, refresh expired");
            return;
        }
        if (identity.refresh_from <= now) {
            this.refreshToken(identity);
            return;
        }

        if (typeof this._identity === 'undefined') {
            this.setIdentity(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established");
        } else if (identity.advertising_token !== this._identity.advertising_token) {
            // identity must have been refreshed from another tab
            this.setIdentity(identity, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
        } else {
            this.setRefreshTimer();
        }
    }

    private createArrayBuffer = (text) => {
        let arrayBuffer = new Uint8Array(text.length);
        for (let i = 0; i < text.length; i++) {
            arrayBuffer[i] = text.charCodeAt(i);
        }
        return arrayBuffer;
    }

    private refreshToken = (identity) => {
        const baseUrl = this.getOptionOrDefault(this._opts.baseUrl, "https://prod.uidapi.com");
        const url = baseUrl + "/v2/token/refresh";
        const req = new XMLHttpRequest();
        this._refreshReq = req;
        req.overrideMimeType("text/plain");
        req.open("POST", url, true);
        req.setRequestHeader('X-UID2-Client-Version', 'uid2-sdk-' + UID2.VERSION);
        req.onreadystatechange = () => {
            this._refreshReq = undefined;
            if (req.readyState !== req.DONE) return;
            try {
                if(this._refreshVersion === 1 || req.status !== 200) {
                    const response = JSON.parse(req.responseText);
                    if (!this.checkResponseStatus(identity, response)) return;
                    this.setIdentity(response.body, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
                } else  if(this._refreshVersion === 2) {
                    let encodeResp = this.createArrayBuffer(atob(req.responseText));
                    window.crypto.subtle.importKey("raw", this.createArrayBuffer(atob(identity.refresh_response_key)),
                        { name: "AES-GCM" }, false, ["decrypt"]
                    ).then((key) => {
                        //returns the symmetric key
                        window.crypto.subtle.decrypt({
                                name: "AES-GCM",
                                iv: encodeResp.slice(0, 12), //The initialization vector you used to encrypt
                                tagLength: 128, //The tagLength you used to encrypt (if any)
                            },
                            key,
                            encodeResp.slice(12)
                        ).then((decrypted) => {
                            const decryptedResponse = String.fromCharCode.apply(String, new Uint8Array(decrypted));
                            const response = JSON.parse(decryptedResponse);
                            if (!this.checkResponseStatus(identity, response)) return;
                            this.setIdentity(response.body, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
                        })
                    })
                }
            } catch (err) {
                this.handleRefreshFailure(identity, err.message);
            }
        };
        req.send(identity.refresh_token);
    };
    private checkResponseStatus = (identity, response) => {
        if (typeof response !== 'object' || response === null) {
            throw new TypeError("refresh response is not an object");
        }
        if (response.status === "optout") {
            this.setFailedIdentity(UID2.IdentityStatus.OPTOUT, "User opted out");
            return false;
        } else if (response.status === "expired_token") {
            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Refresh token expired");
            return false;
        } else if (response.status === "success") {
            if (typeof response.body === 'object' && response.body !== null) {
                return true;
            }
            throw new TypeError("refresh response object does not have a body");
        } else {
            throw new TypeError("unexpected response status: " + response.status);
        }
    };
    private handleRefreshFailure = (identity, errorMessage) => {
        const now = Date.now();
        if (identity.refresh_expires <= now) {
            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Refresh expired; token refresh failed: " + errorMessage);
        } else if (identity.identity_expires <= now && !this.temporarilyUnavailable()) {
            this.setValidIdentity(identity, UID2.IdentityStatus.EXPIRED, "Token refresh failed for expired identity: " + errorMessage);
        } else if (this.initialised()) {
            this.setRefreshTimer(); // silently retry later
        } else {
            this.setIdentity(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established; token refresh failed: " + errorMessage)
        }
    };
    private setRefreshTimer = () => {
        const timeout = this.getOptionOrDefault(this._opts.refreshRetryPeriod, UID2.DEFAULT_REFRESH_RETRY_PERIOD_MS);
        this._refreshTimerId = setTimeout(() => {
            if (this.isLoginRequired()) return;
            this.applyIdentity(this.loadIdentity());
        }, timeout);
    };


}


declare global {
    interface Window {
        googletag: any;
        __uid2: UID2;
    }
}

window.__uid2 = new UID2();

UID2.setupGoogleTag();

export const sdkWindow = globalThis.window;
