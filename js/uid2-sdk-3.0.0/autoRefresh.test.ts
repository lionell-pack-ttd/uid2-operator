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

import {expect, jest, describe, test, beforeEach, afterEach} from '@jest/globals';
import {sdkWindow, UID2} from '../uid2-sdk-3.0.0';
import * as mocks from '../mocks.js';

let callback;
let uid2: UID2;
let xhrMock;
// eslint-disable-next-line no-unused-vars
let cryptoMock;

mocks.setupFakeTime();

beforeEach(() => {
  callback = jest.fn();
  uid2 = new UID2();
  xhrMock = new mocks.XhrMock(sdkWindow);
  cryptoMock = new mocks.CryptoMock(sdkWindow);
  mocks.setCookieMock(sdkWindow.document);
});

afterEach(() => {
  mocks.resetFakeTime();
});

const getUid2Cookie = mocks.getUid2Cookie;
const makeIdentity = mocks.makeIdentityV2;

describe('when auto refreshing a non-expired identity which does not require a refresh', () => {
  beforeEach(() => {
    uid2.init({ callback: callback, identity: makeIdentity() });
    jest.clearAllMocks();
    jest.runOnlyPendingTimers();
  });

  test('should not invoke the callback', () => {
    console.log(sdkWindow.crypto);
    expect(sdkWindow.crypto).toBeDefined();
    expect(callback).not.toHaveBeenCalled();
  });
  test('should not initiate token refresh', () => {
    expect(xhrMock.send).not.toHaveBeenCalled();
  });
  test('should set refresh timer', () => {
    expect(setTimeout).toHaveBeenCalledTimes(1);
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  test('should be in available state', () => {
    (expect(uid2) as any).toBeInAvailableState();
  });
});

describe('when auto refreshing a non-expired identity which requires a refresh', () => {
  const refreshFrom = Date.now() + 100;
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    refresh_from: refreshFrom
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({ callback: callback, identity: originalIdentity });
    jest.clearAllMocks();
    jest.setSystemTime(refreshFrom);
    jest.runOnlyPendingTimers();
  });

  test('should not invoke the callback', () => {
    expect(callback).not.toHaveBeenCalled();
  });
  test('should initiate token refresh', () => {
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
  });
  test('should not set refresh timer', () => {
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  test('should be in available state', () => {
    (expect(uid2) as any).toBeInAvailableState();
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'success', body: updatedIdentity }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: updatedIdentity.advertising_token,
        advertising_token: updatedIdentity.advertising_token,
        status: UID2.IdentityStatus.REFRESHED,
      }));
    });
    test('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    test('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    test('should be in available state', () => {
      (expect(uid2) as any).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'optout' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.OPTOUT,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns refresh token expired', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'expired_token' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should not invoke the callback', () => {
      expect(callback).not.toHaveBeenCalled();
    });
    test('should not update cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    test('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    test('should be in available state', () => {
      (expect(uid2) as any).toBeInAvailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh fails and current identity expires', () => {
    beforeEach(() => {
      jest.setSystemTime(originalIdentity.refresh_expires * 1000 + 1);
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });
});

describe('when auto refreshing an expired identity', () => {
  const refreshFrom = Date.now() + 100;
  const originalIdentity = makeIdentity({
    advertising_token: 'original_advertising_token',
    identity_expires: refreshFrom,
    refresh_from: refreshFrom
  });
  const updatedIdentity = makeIdentity({
    advertising_token: 'updated_advertising_token'
  });

  beforeEach(() => {
    uid2.init({ callback: callback, identity: originalIdentity });
    jest.clearAllMocks();
    jest.setSystemTime(refreshFrom);
    jest.runOnlyPendingTimers();
  });

  test('should not invoke the callback', () => {
    expect(callback).not.toHaveBeenCalled();
  });
  test('should initiate token refresh', () => {
    expect(xhrMock.send).toHaveBeenCalledTimes(1);
  });
  test('should not set refresh timer', () => {
    expect(setTimeout).not.toHaveBeenCalled();
    expect(clearTimeout).not.toHaveBeenCalled();
  });
  test('should be in available state', () => {
    (expect(uid2) as any).toBeInAvailableState();
  });

  describe('when token refresh succeeds', () => {
    beforeEach(() => {
    xhrMock.responseText = btoa(JSON.stringify({ status: 'success', body: updatedIdentity }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: updatedIdentity.advertising_token,
        advertising_token: updatedIdentity.advertising_token,
        status: UID2.IdentityStatus.REFRESHED,
      }));
    });
    test('should set cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(updatedIdentity.advertising_token);
    });
    test('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    test('should be in available state', () => {
      (expect(uid2) as any).toBeInAvailableState(updatedIdentity.advertising_token);
    });
  });

  describe('when token refresh returns optout', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'optout' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.OPTOUT,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns refresh token expired', () => {
    beforeEach(() => {
      xhrMock.responseText = btoa(JSON.stringify({ status: 'expired_token' }));
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });

  describe('when token refresh returns an error status', () => {
    beforeEach(() => {
      xhrMock.responseText = JSON.stringify({ status: 'error', body: updatedIdentity });
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.EXPIRED,
      }));
    });
    test('should not update cookie', () => {
      expect(getUid2Cookie().advertising_token).toBe(originalIdentity.advertising_token);
    });
    test('should set refresh timer', () => {
      expect(setTimeout).toHaveBeenCalledTimes(1);
      expect(clearTimeout).not.toHaveBeenCalled();
    });
    test('should be in temporarily unavailable state', () => {
      (expect(uid2) as any).toBeInTemporarilyUnavailableState(originalIdentity.advertising_token);
    });
  });

  describe('when token refresh fails and current identity expires', () => {
    beforeEach(() => {
      jest.setSystemTime(originalIdentity.refresh_expires * 1000 + 1);
      xhrMock.responseText = JSON.stringify({ status: 'error' });
      xhrMock.onreadystatechange(new Event(''));
    });

    test('should invoke the callback', () => {
      expect(callback).toHaveBeenNthCalledWith(1, expect.objectContaining({
        advertisingToken: undefined,
        advertising_token: undefined,
        status: UID2.IdentityStatus.REFRESH_EXPIRED,
      }));
    });
    test('should clear cookie', () => {
      expect(getUid2Cookie()).toBeUndefined();
    });
    test('should not set refresh timer', () => {
      expect(setTimeout).not.toHaveBeenCalled();
      expect(clearTimeout).toHaveBeenCalledTimes(1);
    });
    test('should be in unavailable state', () => {
      (expect(uid2) as any).toBeInUnavailableState();
    });
  });
});
