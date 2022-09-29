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

import { Uid2ApiClient, Uid2Identity } from './uid2ApiClient';

type PromiseOutcome<T> = {
    resolve: (value: T | PromiseLike<T>) => void;
    reject: (reason: Error) => void;
}
type InitCallbackPayload = {
    advertisingToken: string,
    advertising_token: string,
    status: IdentityStatus,
    statusText: string
}
type InitCallbackFunction = (_: InitCallbackPayload) => void;
type Uid2CallbackHandler = (event: EventType, payload: any) => void;
type Uid2Options = {
    callback?: InitCallbackFunction;
    refreshRetryPeriod?: number;
    identity?: Uid2Identity;
    baseUrl?: string;
    cookieDomain?: string;
    cookiePath?: string;
}
function isUID2OptionsOrThrow(maybeOpts: Uid2Options | unknown): maybeOpts is Uid2Options {
    if (typeof maybeOpts !== 'object' || maybeOpts === null) {
        throw new TypeError('opts must be an object');
    }
    const opts = maybeOpts as Uid2Options;
    if (opts.callback !== undefined && typeof opts.callback !== 'function') {
        throw new TypeError('opts.callback, if provided, must be a function');
    }
    if (typeof opts.refreshRetryPeriod !== 'undefined') {
        if (typeof opts.refreshRetryPeriod !== 'number')
            throw new TypeError('opts.refreshRetryPeriod must be a number');
        else if (opts.refreshRetryPeriod < 1000)
            throw new RangeError('opts.refreshRetryPeriod must be >= 1000');
    }
    return true;
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
enum EventType {
    InitCompleted = 'InitCompleted',
    IdentityUpdated = 'IdentityUpdated',
    SdkLoaded = 'SdkLoaded',
}

class InvalidIdentityError extends Error {
    constructor(message) {
        super(message);
        this.name = "InvalidIdentityError";
    }
}

type UID2CookieOptions = Pick<Uid2Options, 'cookieDomain' | 'cookiePath'> & { cookieName: string };
class UID2CookieManager {
    private _opts: UID2CookieOptions;
    constructor(opts: UID2CookieOptions) {
        this._opts = opts;
    }
    public setCookie(identity) {
        const value = JSON.stringify(identity);
        const expires = new Date(identity.refresh_expires);
        const path = this._opts.cookiePath ?? "/";
        let cookie = this._opts.cookieName + "=" + encodeURIComponent(value) + " ;path=" + path + ";expires=" + expires.toUTCString();
        if (typeof this._opts.cookieDomain !== 'undefined') {
            cookie += ";domain=" + this._opts.cookieDomain;
        }
        document.cookie = cookie;
    }
    public removeCookie() {
        document.cookie = this._opts.cookieName + "=;expires=Tue, 1 Jan 1980 23:59:59 GMT";
    }
    public getCookie() {
        const docCookie = document.cookie;
        if (docCookie) {
            const payload = docCookie.split('; ').find(row => row.startsWith(this._opts.cookieName+'='));
            if (payload) {
                return decodeURIComponent(payload.split('=')[1]);
            }
        }
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
    static EventType = EventType;

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
                if (window.__uid2 && 'getAdvertisingTokenAsync' in window.__uid2) {
                    return window.__uid2.getAdvertisingTokenAsync();
                } else {
                    return Promise.reject(new Error("UID2 SDK not present"));
                }
            },
        });
    }

    public callbacks: Uid2CallbackHandler[] = [];
    constructor() {
        this.runCallbacks(EventType.SdkLoaded, {});
    }


    public init(opts: Uid2Options) {
        this.initInternal(opts);
    }
    public initInternal(opts: Uid2Options | unknown) {
        if (this._initCalled) {
            throw new TypeError('Calling init() more than once is not allowed');
        }

        if (!isUID2OptionsOrThrow(opts)) throw new TypeError(`Options provided to UID2 init couldn't be validated.`);
        
        this._cookieManager = new UID2CookieManager({ ...opts, cookieName: UID2.COOKIE_NAME });
        this._initCalled = true;
        this._opts = opts;

        this._apiClient = new Uid2ApiClient(this._opts.baseUrl ?? "https://prod.uidapi.com", 'uid2-sdk-' + UID2.VERSION);

        const identity = this._opts.identity ? this._opts.identity : this.loadIdentity()
        this.applyIdentity(identity);
        this._initComplete = true;
        this.runCallbacks(EventType.InitCompleted, {});

    }
    public getAdvertisingToken() {
        return this._identity && !this.temporarilyUnavailable() ? this._identity.advertising_token : undefined;
    }
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
    }
    public isLoginRequired() {
        return this.initialised() ? !this._identity : undefined;
    }
    public disconnect() {
        this.abort();

        // TODO: This silently fails to clear the cookie if init hasn't been called and a cookieDomain is used
        if (this._cookieManager) this._cookieManager.removeCookie();
        else new UID2CookieManager({ cookieName: UID2.COOKIE_NAME }).removeCookie();

        this._identity = undefined;
        this._lastStatus = UID2.IdentityStatus.INVALID;

        const promises = this._promises;
        this._promises = [];
        promises.forEach(p => p.reject(new Error("disconnect()")));
        this.runCallbacks(UID2.EventType.IdentityUpdated, { identity: null });
    }
    public abort() {
        this._initCalled = true;
        if (typeof this._refreshTimerId !== 'undefined') {
            clearTimeout(this._refreshTimerId);
            this._refreshTimerId = undefined;
        }
        if (this._apiClient) this._apiClient.abortActiveRequests();
    }

    // PRIVATE STATE
    
    _initCalled = false;
    _opts;
    _identity;
    _lastStatus;
    _refreshTimerId;
    _refreshVersion;
    _promises: PromiseOutcome<string>[] = [];
    private _initComplete = false;  // Whether init has finished
    private _cookieManager: UID2CookieManager;
    private _apiClient: Uid2ApiClient;

    private _configuredCallbackArray = false;
    private static _sentSdkLoaded = false;
    private _sentInit = false;
    private callbackPushInterceptor(...args) {
        const pushResult = Array.prototype.push.apply(this.callbacks, args);
        for (const c of args) {
            if (UID2._sentSdkLoaded) this.safeRunCallback(c, EventType.SdkLoaded, { });
            if (this._sentInit) this.safeRunCallback(c, EventType.InitCompleted, { identity: this._identity });
        }
        return pushResult;
    }
    private runCallbacks(event: EventType, payload) {
        if (!(this._initComplete || event === EventType.SdkLoaded )) return;

        if (!this._configuredCallbackArray) {
            this.callbacks.push = this.callbackPushInterceptor.bind(this);
            this._configuredCallbackArray = true;
        }
        const enrichedPayload = { ...payload, identity: this._identity };
        for (const callback of this.callbacks) {
            this.safeRunCallback(callback, event, enrichedPayload);
        }
        if (event === EventType.SdkLoaded) UID2._sentSdkLoaded = true;
        if (event === EventType.InitCompleted) this._sentInit = true;
    }
    private safeRunCallback(callback: Uid2CallbackHandler, event: EventType, payload) {
        if (typeof callback === 'function') {
            try {
                callback(event, payload);
            } catch (exception) {
                console.warn("UID2 callback threw an exception", exception);
            }
        } else {
            console.warn("A UID2 SDK callback was supplied which isn't a function.")
        }
    }

    private initialised() {
        return typeof this._lastStatus !== 'undefined'; 
    }
    private temporarilyUnavailable() {
        return this._lastStatus === UID2.IdentityStatus.EXPIRED; 
    }

    private getOptionOrDefault(value, defaultValue) {
        return typeof value === 'undefined' ? defaultValue : value;
    }

    private updateStatus(status, statusText) {
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
    }
    private setValidIdentity(identity, status, statusText) {
        this._identity = identity;
        this._cookieManager.setCookie(identity);
        this.setRefreshTimer();
        this.updateStatus(status, statusText);
    }
    private setFailedIdentity(status, statusText) {
        this._identity = undefined;
        this.abort();
        this._cookieManager.removeCookie();
        this.updateStatus(status, statusText);
    }
    private checkIdentity(identity) {
        if (!identity.advertising_token) {
            throw new InvalidIdentityError("advertising_token is not available or is not valid");
        } else if (!identity.refresh_token) {
            throw new InvalidIdentityError("refresh_token is not available or is not valid");
        } else if (identity.refresh_response_key) {
            this._refreshVersion = 2;
        } else {
            this._refreshVersion = 1;
        }
    }
    private tryCheckIdentity(identity) {
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
    }
    private setIdentity(identity, status, statusText) {
        if (this.tryCheckIdentity(identity)) {
        this.setValidIdentity(identity, status, statusText);
        }
    }
    private loadIdentity() {
        const payload = this._cookieManager.getCookie();
        if (payload) {
            return JSON.parse(payload);
        }
    }

    private enrichIdentity(identity, now) {
        return {
            refresh_from: now,
            refresh_expires: now + 7 * 86400 * 1000, // 7 days
            identity_expires: now + 4 * 3600 * 1000, // 4 hours
            ...identity,
        };
    }
    private applyIdentity(identity) {
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

    private refreshToken(identity) {
        this._apiClient.callRefreshApi(identity)
            .then((response) => {
                    switch (response.status) {
                        case 'success':
                            this.setIdentity(response.identity, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
                            break;
                        case 'optout':
                            this.setFailedIdentity(UID2.IdentityStatus.OPTOUT, "User opted out");
                            break;
                        case 'expired_token':
                            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Refresh token expired");
                            break;
                    }
                },
                (reason) => {
                    this.handleRefreshFailure(identity, reason.message);
                }
            )
            .then(() => {
                this.runCallbacks(EventType.IdentityUpdated, {});
            });
    }
    private handleRefreshFailure(identity, errorMessage) {
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
    }
    private setRefreshTimer() {
        const timeout = this.getOptionOrDefault(this._opts.refreshRetryPeriod, UID2.DEFAULT_REFRESH_RETRY_PERIOD_MS);
        this._refreshTimerId = setTimeout(() => {
            if (this.isLoginRequired()) return;
            this.applyIdentity(this.loadIdentity());
        }, timeout);
    }


}

type UID2Setup = {
    callbacks: Uid2CallbackHandler[] | undefined;
}
declare global {
    interface Window {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        googletag: any;
        __uid2: UID2 | UID2Setup | undefined;
    }
}

(function() {
    const callbacks = window?.__uid2?.callbacks || [];
    window.__uid2 = new UID2();
    window.__uid2.callbacks = callbacks;
})();

UID2.setupGoogleTag();

export const sdkWindow = globalThis.window;
