import { safeGetErrorMessage } from "./uid2-sdk-3.0.0";

interface IdentityBase {
    advertising_token: string;
    identity_expires: number;
    refresh_from: number;
    refresh_token: string;
    refresh_expires: number;
}
interface IdentityV2 extends IdentityBase {
    // eslint-disable-next-line camelcase
    refresh_response_key: string;
}
interface IdentityV1 extends IdentityBase {
    // eslint-disable-next-line camelcase
    refresh_response_key: never;
}
export type Uid2Identity = IdentityV1 | IdentityV2;
export function isValidIdentity(identity: Uid2Identity | unknown): identity is Uid2Identity {
    return (typeof identity === 'object' &&
        identity !== null &&
        'advertising_token' in identity &&
        'identity_expires' in identity &&
        'refresh_from' in identity &&
        'refresh_token' in identity &&
        'refresh_expires' in identity
    );
}

export type RefreshResultWithoutIdentity = { status: ResponseStatusWithoutBody };
export type SuccessRefreshResult = {
    status: ResponseStatusRequiringBody;
    identity: Uid2Identity;
};
export type RefreshResult = SuccessRefreshResult | RefreshResultWithoutIdentity;

type RefreshApiResponse = {
    status: ResponseStatusRequiringBody;
    body: Uid2Identity;
} | {
    status: ResponseStatusWithoutBody;
};
export type ResponseStatus = ResponseStatusRequiringBody | ResponseStatusWithoutBody;
type ResponseStatusRequiringBody = "success";
type ResponseStatusWithoutBody = "optout" | "expired_token"
type UnvalidatedRefreshResponse = RefreshApiResponse | {status: unknown};
function isValidRefreshResponse(response: unknown | UnvalidatedRefreshResponse): response is RefreshApiResponse {
    if (isUnvalidatedRefreshResponse(response)) {
        return response.status === "optout" || response.status === "expired_token" ||
            (response.status === "success" && 'body' in response && isValidIdentity(response.body));
    }
    return false;
}
function isUnvalidatedRefreshResponse(response: unknown): response is UnvalidatedRefreshResponse {
    return typeof(response) === 'object' && response !== null && 'status' in response;
}

export class Uid2ApiClient {
    private _baseUrl: string;
    private _clientVersion: string;
    private _requestsInFlight: XMLHttpRequest[] = [];
    constructor(baseUrl: string, clientVersion: string) {
        this._baseUrl = baseUrl;
        this._clientVersion = clientVersion;
    }

    private createArrayBuffer(text: string) {
        const arrayBuffer = new Uint8Array(text.length);
        for (let i = 0; i < text.length; i++) {
            arrayBuffer[i] = text.charCodeAt(i);
        }
        return arrayBuffer;
    }

    public hasActiveRequests() {
        return this._requestsInFlight.length > 0;
    }

    private ResponseToRefreshResult(response: UnvalidatedRefreshResponse | unknown): RefreshResult | string {
        if (isValidRefreshResponse(response)) {
            if (response.status === "success") return { status: response.status, identity: response.body };
            return response;
        } else return "Response didn't contain a valid status";
    }

    public abortActiveRequests() {
        this._requestsInFlight.forEach(req => {
            req.abort();
        });
        this._requestsInFlight = [];
    }

    public callRefreshApi(refreshDetails: Uid2Identity): Promise<RefreshResult> {
        const url = this._baseUrl + "/v2/token/refresh";
        const req = new XMLHttpRequest();
        this._requestsInFlight.push(req);
        req.overrideMimeType("text/plain");
        req.open("POST", url, true);
        req.setRequestHeader('X-UID2-Client-Version', this._clientVersion);
        let resolvePromise: (result: RefreshResult) => void;
        let rejectPromise: (reason: string) => void;
        const promise = new Promise<RefreshResult>((resolve, reject) => {
            resolvePromise = resolve;
            rejectPromise = reject;
        });
        req.onreadystatechange = () => {
            if (req.readyState !== req.DONE) return;
            this._requestsInFlight = this._requestsInFlight.filter(r => r !== req);
            try {
                if(!refreshDetails.refresh_response_key || req.status !== 200) {
                    const response = JSON.parse(req.responseText) as unknown;
                    const result = this.ResponseToRefreshResult(response);
                    if (typeof result === 'string') rejectPromise(result);
                    else resolvePromise(result);
                } else {
                    const encodeResp = this.createArrayBuffer(atob(req.responseText));
                    window.crypto.subtle.importKey("raw", this.createArrayBuffer(atob(refreshDetails.refresh_response_key)),
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
                            const decryptedResponse = String.fromCharCode(...new Uint8Array(decrypted));
                            const response = JSON.parse(decryptedResponse) as unknown;
                            const result = this.ResponseToRefreshResult(response);
                            if (typeof result === 'string') rejectPromise(result);
                            else resolvePromise(result);
                        }, (reason) => console.warn(`Call to UID2 API failed with reason: ${safeGetErrorMessage(reason)}`))
                    }, (reason) => console.warn(`Call to UID2 API failed with reason: ${safeGetErrorMessage(reason)}`))
                }
            } catch (err) {
                rejectPromise(safeGetErrorMessage(err));
            }
        };
        req.send(refreshDetails.refresh_token);
        return promise;
    }
}
