# oAuth2.0
## the 4 oauth rules
1. resource owner: me (app owner)
2. the client: end users that use my app (owners app) try to access the data
3. the authorization server: the server that logs the user in and issues tokens auth server
4. resource server: the api holding protected data resource server

- Tokens: are like authorization code
- Access token: short-lived token to call api's while we use
- Refresh token: a long lived token used to get new access token

- *PKCE* code_verifier, code_challenge, code_challenge in /authorize, /token -> code_verifier, code_verifier -> code_challenge

### jose
jose is a JavaScript module for JSON Object Signing and Encryption, providing support for JSON Web Tokens (JWT), JSON Web Signature (JWS), JSON Web Encryption (JWE), JSON Web Key (JWK), JSON Web Key Set (JWKS), and more

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem 
```

```bash
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem
```