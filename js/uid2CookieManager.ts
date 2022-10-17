// Copyright (c) 2022 The Trade Desk, Inc
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

import { Uid2Options } from "./uid2-sdk-3.0.0";
import { Uid2Identity } from './uid2ApiClient';

type UID2CookieOptions = Pick<Uid2Options, 'cookieDomain' | 'cookiePath'> & { cookieName: string };

export class UID2CookieManager {
    private _opts: UID2CookieOptions;
    constructor(opts: UID2CookieOptions) {
        this._opts = opts;
    }
    public setCookie(identity: Uid2Identity) {
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
