import {
  createAuthzHeader, createSignatureString,
  parseRequest, parseSignatureHeader,
  // @ts-expect-error no types
} from '@digitalbazaar/http-signature-header';

import { base64ToBase64Url, base64urlToBase64 } from "./base64.js"
import { bytesFromBase64, bytesToBase64 } from "./base64.js"
import { DID, DIDKeyVerificationMethodId } from "./did.js";
import { ISigner } from './types.js';

export async function createRequestWithHttpSignature(
  url: URL,
  options: {
    body?: Blob | Uint8Array | string | null | FormData
    method?: string,
    signer: ISigner
    headers?: Record<string,string>,
    /** @example ['(created)', '(key-id)', '(request-target)'] */
    includeHeaders: string[],
    created?: Date,
    expires?: Date,
  }
): Promise<Request> {
  const created = options.created || new Date
  const expires = options.expires || new Date(Date.now() + 30 * 1000)
  const headers = options.headers ?? {}
  if ( ! headers.host && options.includeHeaders.includes('host')) {
    headers.host = url.host
  }
  const method = options.method ?? 'GET'
  if (options.includeHeaders.includes('(created)') && !headers.date && options.created) {
    headers.date = options.created.toUTCString()
  }
  const authorization = await createHttpSignatureAuthorization({
    signer: options.signer,
    url: url,
    method,
    headers,
    includeHeaders: options.includeHeaders,
    created,
    expires,
  })
  const request = new Request(url, {
    body: options.body,
    method,
    headers: {
      ...headers,
      authorization,
    }
  })
  return request
}

export async function createHttpSignatureAuthorization(options: {
  signer: ISigner
  url: URL
  method: string,
  headers: Record<string,string>,
  includeHeaders: string[],
  created: Date,
  expires?: Date,
}): Promise<string> {
  const { url, method, headers, includeHeaders } = options
  const urlString = url.toString()
  const requestOptions = {
    url: urlString,
    method,
    headers,
    keyId: options.signer.id,
    created: options.created,
    expires: options.expires,
  }
  const plainTextToSign = createSignatureString({ requestOptions, includeHeaders })
  // console.debug('signingString for new http signature', {
  //   signingString: plainTextToSign,
  //   includeHeaders: options.includeHeaders,
  // })
  const toSign = new TextEncoder().encode(plainTextToSign)
  const signature = await options.signer.sign({data:toSign})
  const signatureB64Url = base64ToBase64Url(bytesToBase64(signature))
  const authorization = createAuthzHeader({
    includeHeaders,
    keyId: options.signer.id,
    signature: signatureB64Url,
    created: options.created,
    expires: options.expires,
  }) as string
  return authorization
}

function headersToObject(headers: Headers) {
  const object = {}
  headers.forEach((headerValue, headerName) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (object as any)[headerName] = headerValue
  })
  return object
}

interface SignatureVerifier {
  verify(options: {
    data: Uint8Array,
    signature: Uint8Array,
  }): Promise<boolean>
}

export class HttpSignatureAuthorization {
  static async verified(request: Request, options: {
    getVerifier(keyId: string): Promise<SignatureVerifier>
  }) {
    const headersObject = headersToObject(request.headers)
    const parsed = parseRequest({
      url: request.url.toString(),
      method: request.method,
      headers: headersObject,
    }, {
      headers: ['(key-id)', '(created)', '(expires)', '(request-target)', 'host']
    })
    const keyId = parsed.params.keyId
    const headers = parsed.params.headers

    // now actually verify the signature
    const actualSignatureBytes = bytesFromBase64(base64urlToBase64(parsed.params.signature))
    {
      // compare expected sign(dataFromRequest) with actual signature
      const expectedSigningString = parsed.signingString
      const expectedSignedBytes = new TextEncoder().encode(expectedSigningString)
      const verifier = await options.getVerifier(keyId)
      // console.debug('HttpSignatureAuthorization#verified checking signature', {
      //   expectedSigningString,
      //   parsed,
      // })
      const verified = await verifier.verify({
        data: expectedSignedBytes,
        signature: actualSignatureBytes,
      })
      if (verified !== true) {
        throw new Error(`unable to verify http signature`)
      }
    }

    return new VerifiedHttpSignatureAuthorization({
      keyId,
      signedParameters: headers,
      signature: actualSignatureBytes,
      created: UnixTimestamp.from(parsed.params.created),
      expires: UnixTimestamp.from(parsed.params.expires),
    })
  }
}

function dateToUnixTimestamp(d: Date) {
  return Math.floor(d.getTime() / 1000)
}

export class UnixTimestamp {
  secondsSinceEpoch: number
  static from(input: string|Date) {
    if (typeof input === "string") {
      const unixTimestamp = parseInt(input)
      return new UnixTimestamp(unixTimestamp)
    }
    return new UnixTimestamp(dateToUnixTimestamp(input))
  }
  constructor(seconds: number) {
    this.secondsSinceEpoch = seconds
  }
  toNumber() {
    return this.secondsSinceEpoch
  }
}

export class VerifiedHttpSignatureAuthorization extends HttpSignatureAuthorization {
  keyId: DIDKeyVerificationMethodId
  signedParameters: string[]
  signature: Uint8Array
  created: UnixTimestamp
  expires?: UnixTimestamp
  constructor(options: {
    keyId: DIDKeyVerificationMethodId
    signedParameters: string[]
    signature: Uint8Array
    created: UnixTimestamp
    expires?: UnixTimestamp
  }) {
    super()
    this.keyId = options.keyId
    this.signedParameters = options.signedParameters
    this.signature = options.signature
    this.created = options.created
    this.expires = options.expires
  }
}
