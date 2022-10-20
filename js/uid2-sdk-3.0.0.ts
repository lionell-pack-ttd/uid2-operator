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

import { MakeOptional } from './helperTypes/index';
import { Uid2ApiClient, Uid2Identity } from './uid2ApiClient';
import { EventType, IdentityStatus, InitCallbackFunction, Uid2CallbackHandler, Uid2CallbackManager } from './uid2CallbackManager';
import { UID2CookieManager } from './uid2CookieManager';
import { UID2PromiseHandler } from './uid2PromiseHandler';


export type Uid2Options = {
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
function setupGoogleTag() {
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
function hasExpired(expiry: number, now=Date.now()) {
    return expiry <= now;
}

export class UID2 {
    private _tokenPromiseHandler: UID2PromiseHandler;
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
    static setupGoogleTag = setupGoogleTag;

    public callbacks: Uid2CallbackHandler[] = [];
    constructor(existingCallbacks: Uid2CallbackHandler[] | undefined = undefined) {
        if (existingCallbacks) this.callbacks = existingCallbacks;

        this._tokenPromiseHandler = new UID2PromiseHandler(this);

        this._callbackManager = new Uid2CallbackManager(this, () => this._identity);
        this._callbackManager.runCallbacks(EventType.SdkLoaded, {});
    }

    public init(opts: Uid2Options) {
        this.initInternal(opts);
    }
    public initInternal(opts: Uid2Options | unknown) {
        if (this._initComplete) {
            throw new TypeError('Calling init() more than once is not allowed');
        }
        if (!isUID2OptionsOrThrow(opts)) throw new TypeError(`Options provided to UID2 init couldn't be validated.`);
        
        this._cookieManager = new UID2CookieManager({ ...opts, cookieName: UID2.COOKIE_NAME });
        this._opts = opts;
        this._apiClient = new Uid2ApiClient(this._opts.baseUrl ?? "https://prod.uidapi.com", 'uid2-sdk-' + UID2.VERSION);

        const identity = this._opts.identity ? this._opts.identity : this.loadIdentityFromCookie()
        this.applyIdentity(identity);
        this._initComplete = true;
        this._callbackManager?.runCallbacks(EventType.InitCompleted, {});
    }
    public getAdvertisingToken() {
        return this._identity && !this.temporarilyUnavailable() ? this._identity.advertising_token : undefined;
    }
    // If the SDK has been initialized, returns a resolved promise with the current token (or rejected if not available)
    // Otherwise, returns a promise which will be resolved after init.
    public getAdvertisingTokenAsync() {
        const token = this.getAdvertisingToken();
        return this._tokenPromiseHandler.createMaybeDeferredPromise(token ?? null);
    }
    public isLoginRequired() {
        if (!this._initComplete) return undefined;
        return !(this.isLoggedIn() || this._apiClient?.hasActiveRequests());
    }
    public disconnect() {
        this.abort(`UID2 SDK disconnected.`);
        // Note: This silently fails to clear the cookie if init hasn't been called and a cookieDomain is used!
        if (this._cookieManager) this._cookieManager.removeCookie();
        else new UID2CookieManager({ cookieName: UID2.COOKIE_NAME }).removeCookie();
        this._identity = undefined;
        this._callbackManager.runCallbacks(UID2.EventType.IdentityUpdated, { identity: null });
    }
    
    // Note: This doesn't invoke callbacks. It's a hard, silent reset.
    public abort(reason?: string) {
        this._initComplete = true;
        this._tokenPromiseHandler.rejectAllPromises(reason ?? new Error(`UID2 SDK aborted.`));
        if (typeof this._refreshTimerId !== 'undefined') {
            clearTimeout(this._refreshTimerId);
            this._refreshTimerId = undefined;
        }
        if (this._apiClient) this._apiClient.abortActiveRequests();
    }

    private _opts: Uid2Options | null = null;
    private _identity: Uid2Identity | null | undefined;
    private _initComplete = false;

    private _cookieManager: UID2CookieManager | undefined;
    private _apiClient: Uid2ApiClient | undefined;
    private _callbackManager: Uid2CallbackManager;
    
    private isLoggedIn() {        
        return this._identity && !hasExpired(this._identity.refresh_expires);
    }


    private temporarilyUnavailable() {
        if (!this._identity && this._apiClient?.hasActiveRequests()) return true;
        if (this._identity && hasExpired(this._identity.identity_expires) && !hasExpired(this._identity.refresh_expires)) return true;
        return false;
    }

    private updateStatus(status: any, statusText: string) {
        const advertisingToken = this.getAdvertisingToken();

        const result = {
            advertisingToken: advertisingToken,
            advertising_token: advertisingToken,
            status: status,
            statusText: statusText
        };
        if (this._opts?.callback) this._opts.callback(result);
    }
    
    private setValidIdentity(identity: Uid2Identity, status: any, statusText: string) {
        if (!this._cookieManager) throw new Error("Cannot set identity before calling init.")

        this._identity = identity;
        this._cookieManager.setCookie(identity);
        this.updateStatus(status, statusText);
    }
    private setFailedIdentity(status: any, statusText: string) {
        if (!this._cookieManager) throw new Error("Cannot set identity before calling init.")

        this._identity = undefined;
        this.abort();
        this._cookieManager.removeCookie();
        this.updateStatus(status, statusText);
    }

    private tryCheckIdentity(identity: Uid2Identity): {valid: true} | {valid: false, errorMessage: string} {
        if (!identity.advertising_token) {            
            return { valid: false, errorMessage: "advertising_token is not available or is not valid" };
        } else if (!identity.refresh_token) {
            return { valid: false, errorMessage: "refresh_token is not available or is not valid" };
        }
        return { valid: true };
    }
    private setIdentityWithChecks(identity: Uid2Identity, status: any, statusText: string) {
        const validity = this.tryCheckIdentity(identity);
        if (validity.valid) {
            this.setValidIdentity(identity, status, statusText);
        } else {            
            this.setFailedIdentity(UID2.IdentityStatus.INVALID, validity.errorMessage);
        }
    }
    private loadIdentityFromCookie() {
        if (!this._cookieManager) throw new Error("Cannot load identity before calling init.")

        const payload = this._cookieManager.getCookie();
        if (payload) {
            return JSON.parse(payload);
        }
    }

    private enrichIdentity(identity: MakeOptional<Uid2Identity, 'refresh_from' | 'refresh_expires' | 'identity_expires'>, now: number) {
        return {
            refresh_from: now,
            refresh_expires: now + 7 * 86400 * 1000, // 7 days
            identity_expires: now + 4 * 3600 * 1000, // 4 hours
            ...identity,
        };
    }
    private applyIdentity(identity: Uid2Identity) {
        if (!identity) {
            this.setFailedIdentity(UID2.IdentityStatus.NO_IDENTITY, "Identity not available");
            return;
        }

        const validity = this.tryCheckIdentity(identity);
        if (!validity.valid) {
            this.setFailedIdentity(UID2.IdentityStatus.INVALID, validity.errorMessage);
            return;
        }

        const now = Date.now();
        identity = this.enrichIdentity(identity, now);
        if (hasExpired(identity.refresh_expires, now)) {
            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Identity expired, refresh expired");
            return;
        }

        if (!hasExpired(identity.identity_expires, now)) {
            if (typeof this._identity === 'undefined') {
                this.setIdentityWithChecks(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established");
            } else if (identity.advertising_token !== this._identity?.advertising_token) {
                // identity must have been refreshed from another tab
                this.setIdentityWithChecks(identity, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
            } 
        }
        
        if (hasExpired(identity.refresh_from, now)) {
            this.refreshToken(identity);
        } else {
            this.setRefreshTimer();
        }
    }

    private refreshToken(identity: Uid2Identity) {
        if (!this._apiClient) throw new Error("Cannot refresh the token before calling init.")

        this._apiClient.callRefreshApi(identity)
            .then((response) => {
                    switch (response.status) {
                        case 'success':
                            this.setIdentityWithChecks(response.identity, UID2.IdentityStatus.REFRESHED, "Identity refreshed");
                            this.setRefreshTimer();
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
                this._callbackManager.runCallbacks(EventType.IdentityUpdated, {});
            });
    }
    private handleRefreshFailure(identity: Uid2Identity, errorMessage: string) {
        const now = Date.now();
        if (hasExpired(identity.refresh_expires, now)) {
            this.setFailedIdentity(UID2.IdentityStatus.REFRESH_EXPIRED, "Refresh expired; token refresh failed: " + errorMessage);
            return;
        }
        
        if (hasExpired(identity.identity_expires, now)) {
            this.setValidIdentity(identity, UID2.IdentityStatus.EXPIRED, "Token refresh failed for expired identity: " + errorMessage);
        } else {
            this.setIdentityWithChecks(identity, UID2.IdentityStatus.ESTABLISHED, "Identity established; token refresh failed: " + errorMessage)
        }
        this.setRefreshTimer();
    }

    private _refreshTimerId: any;
    private setRefreshTimer() {
        const timeout = this._opts?.refreshRetryPeriod ?? UID2.DEFAULT_REFRESH_RETRY_PERIOD_MS;
        this._refreshTimerId = setTimeout(() => {
            if (this.isLoginRequired()) return;
            this.applyIdentity(this.loadIdentityFromCookie());
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
    window.__uid2 = new UID2(callbacks);
})();

UID2.setupGoogleTag();

export const sdkWindow = globalThis.window;
