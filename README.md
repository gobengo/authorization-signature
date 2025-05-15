# authorization-signature

Create HTTP Authorization header values for [HTTP Message Signatures](https://oauth.net/http-signatures/).

## Usage

### byexample

These snippets should pass [byexample](https://byexamples.github.io/byexample/languages/javascript)

> byexample -l javascript README.md

```javascript
> const { Ed25519Signer } = await import("@did.coop/did-key-ed25519")
> const { createRequestWithHttpSignature } = await import("authorization-signature");
> const signer = await Ed25519Signer.generate()
> const url = new URL('http://example.com')
> const request = await createRequestWithHttpSignature( // byexample: +timeout=100
.   url,
.   {
.      includeHeaders: [
.        '(key-id)',
.        '(request-target)',
.        'host',
.      ],
.      signer,
.    }
.  )
> request.headers.get('authorization')?.startsWith('Signature ')
true
```
