# Rante Login SDK for .NET

"Sign in with Rante" on your .NET server. The SDK:

- builds the sign-in request (authorization code with PKCE, state and nonce);
- exchanges the code, proving it is your app with `private_key_jwt`, or with PKCE alone for browser-only apps;
- validates the ID token before you trust who signed in;
- calls the userinfo endpoint.

It finishes sign-ins started by the [Rante Login browser SDK](https://github.com/rante-corporation/rante-login-sdk)
too, including FedCM sign-ins in Chrome and Edge.

The SDK is a thin layer over
[Microsoft.IdentityModel](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet):
`JsonWebTokenHandler` handles the JWTs, and `ConfigurationManager` caches the discovery document and the signing keys.
It targets .NET 8 and .NET 10.

ASP.NET Core's OpenID Connect handler can't finish a sign-in that the browser SDK started, because it creates its own
state, nonce and PKCE values. This SDK works with either.

## Install

The package isn't on NuGet. Reference the project from a clone:

```sh
git clone https://github.com/rante-corporation/rante-login-sdk-dotnet
dotnet add reference rante-login-sdk-dotnet/src/Rante.Login/Rante.Login.csproj
```

## Register your app

1. Sign in to the Rante Portal and register an app at <https://portal.rante.com/dev/apps>.
2. On the app's page, turn on Rante Login and add your redirect URI, for example
   `https://shop.example.com/auth/rante/callback`. Use `http://localhost:3000/auth/rante/callback` for the example
   in this repository.
3. Choose which information your site asks for (at least **Name**).
4. Choose the website type:
   - **Server-side website** (recommended for this SDK): your server proves itself with a Signed JWT key linked to
     the app.
     1. Make a key pair:
        `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out private.pem`, or
        `-algorithm EC -pkeyopt ec_paramgen_curve:P-256` for ES256.
     2. Make the public key: `openssl pkey -in private.pem -pubout -out public.pem`.
     3. At <https://portal.rante.com/dev/apikeys>, create a key with the **Signed JWT (RS256 or ES256)** method and paste
        `public.pem`.
     4. Link the key to the app, and note its prefix (`rk_live_…`).

     `private.pem` stays on your server.
   - **Browser-only website**: no key. The SDK sends only the PKCE verifier.
5. Copy the app's **Application (client) ID**.

## Sign people in

```csharp
using Rante.Login;

var rante = new RanteLoginClient(new RanteLoginOptions
{
    ClientId = builder.Configuration["RANTE_LOGIN_CLIENT_ID"]!,
    RedirectUri = "https://shop.example.com/auth/rante/callback",
    // A server-side website. Leave SigningKey out for a browser-only website.
    SigningKey = RanteLoginSigningKey.FromPem(builder.Configuration["RANTE_LOGIN_KEY_PREFIX"]!, File.ReadAllText("private.pem")),
});
builder.Services.AddSingleton(rante); // one client per app: it caches the discovery document and the keys

// 1. Send the browser to Rante Login, and keep the rest of the request in the server-side session.
app.MapGet("/auth/rante/sign-in", async (HttpContext context) =>
{
    var request = await rante.CreateAuthorizationRequestAsync();
    context.Session.SetString("rante", JsonSerializer.Serialize(request.ToExpected()));
    return Results.Redirect(request.Url);
});

// 2. At the redirect URI: check the response, exchange the code and validate the ID token.
app.MapGet("/auth/rante/callback", async (HttpContext context) =>
{
    var expected = context.Session.GetString("rante") is { } json ? JsonSerializer.Deserialize<ExpectedTransaction>(json) : null;
    context.Session.Remove("rante"); // each request is used once
    var result = await rante.HandleCallbackAsync(context.Request.Query, expected);
    // result.Subject is the person's ID on your website. It's pairwise: the same for your organization's apps, and
    // different for other organizations. result.IdToken.Identity can sign them in with cookie authentication.
});
```

`HandleCallbackAsync` throws a `RanteLoginException` unless all of these hold:

- `state` matches;
- the response came from Rante Login (`iss`, [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207));
- the token endpoint accepted the code;
- the ID token is valid. Specifically:
  - its RS256 signature checks out with the key that its `kid` names in Rante Login's JWKS;
  - `iss` is `https://login.rante.com/common/v2.0`;
  - `aud` is your client ID (and `azp`, when present);
  - `nonce` matches;
  - `exp` hasn't passed (a minute of clock skew is allowed);
  - `iat` and `sub` are present.

Rante Login releases an email address only once the person has verified it.

### Sign-ins started by the browser SDK

Your page can show the "Sign in with Rante" button instead, using the browser SDK with `serverSide: true`:

- **Redirect sign-ins:** the SDK keeps the PKCE verifier, state and nonce in the `rante_login_pkce`,
  `rante_login_state` and `rante_login_nonce` cookies. Read them at the redirect URI, then clear them:

  ```csharp
  var expected = RanteLoginClient.FromBrowserSdkCookies(context.Request.Cookies);
  foreach (var name in BrowserSdkCookies.All) context.Response.Cookies.Delete(name, new CookieOptions { Path = "/" });
  var result = await rante.HandleCallbackAsync(context.Request.Query, expected);
  ```

- **FedCM sign-ins** (Chrome and Edge): the ID token comes back to the page, which posts it to your server. Because
  the page could choose any nonce, issue one per session on the server, and pass it to
  `RanteLogin.renderButton(element, { nonce })`. Then check the token against it:

  ```csharp
  var token = await rante.ValidateIdTokenAsync(idToken, context.Session.GetString("nonce")!);
  ```

### Userinfo

```csharp
var userinfo = await rante.FetchUserInfoAsync(result.AccessToken, expectedSubject: result.Subject);
```

The access token from the code exchange lasts 15 minutes. FedCM sign-ins return no access token.

## Registering people with their Rante account

A person's first "Sign in with Rante" on your website is their sign-up, like "Sign up with Google". Create your
website's account from the claims they agreed to share, keyed by `sub`. Every later sign-in finds the same account, so
your website needs no sign-up form and no password of its own.

```csharp
// After HandleCallbackAsync (redirect) or ValidateIdTokenAsync (FedCM): these claims are validated.
var account = await db.Accounts.SingleOrDefaultAsync(a => a.RanteSub == result.Subject);
if (account is null)
{
    account = new Account
    {
        RanteSub = result.Subject,
        Name = result.Claims.GetValueOrDefault("name") as string,
        Email = result.Claims.GetValueOrDefault("email") as string,
    };
    db.Accounts.Add(account);
    await db.SaveChangesAsync();
}
```

- **Key the account on `sub`, never on email.** Email can change, and Rante shares it only once it's verified. If you
  accept more than one sign-in provider, key on the issuer and `sub` together.
- **`sub` is pairwise:** the same for every app of your organization, different for other organizations.
- **Linking an existing account:** have the person sign in to that account first, then store their `sub` on it. Don't
  link accounts because their emails match.
- **Ask only for what you need.** You choose the items in the Portal. Optional items may be missing, so give them
  defaults.

The example does this on every sign-in and shows the result under "Your account on this website". It keeps
its accounts in memory, so they are gone when the server restarts.

## API

| | |
|---|---|
| `new RanteLoginClient(RanteLoginOptions)` | Options: `ClientId`, `RedirectUri`, `Scope` (default `openid profile email`; request only scopes whose information the app asks for), `SigningKey`, `Issuer`, `HttpClient`, `Timeout` (default 10 s) and `ClockSkew` (default 1 minute). |
| `RanteLoginSigningKey.FromPem(keyPrefix, pem)`, `FromRsa`, `FromECDsa` | An RSA key of at least 2048 bits (RS256) or an EC P-256 key (ES256). |
| `CreateAuthorizationRequestAsync(AuthorizationRequestOptions?)` | Options: `Nonce`, `Prompt`, `LoginHint` and `MaxAge`. Returns an `AuthorizationRequest` with `Url`, `State`, `Nonce` and `CodeVerifier`, plus `ToExpected()`. |
| `HandleCallbackAsync(query, expected)` | `query` is `Request.Query`, the callback URL, or its query string. Returns a `RanteLoginResult` with `Subject`, `Claims`, `IdToken` (`Subject`, `Claims`, `Identity`), `AccessToken` and `Tokens`. |
| `ExchangeCodeAsync(code, codeVerifier)` | The token request on its own. Returns a `TokenResponse`. |
| `ValidateIdTokenAsync(idToken, nonce)` | Returns a `ValidatedIdToken`. |
| `FetchUserInfoAsync(accessToken, expectedSubject?)` | Returns a `UserInfo` with `Subject` and `Claims`. |
| `RanteLoginClient.FromBrowserSdkCookies(Request.Cookies)` or `(cookieHeader)` | Returns an `ExpectedTransaction`, or `null` when a cookie is missing. |
| `ClientAuthentication` | `"private_key_jwt"` or `"none"`. |

### Errors

Every failure is a `RanteLoginException` with a stable `Code`, and a `Status` when the error came from Rante Login:

| Code | Meaning |
|---|---|
| `invalid_configuration` | A setting or key is wrong; the message says which. |
| `missing_transaction` | No expected values: the session or the browser SDK's cookies are gone. They last 10 minutes and must be on the redirect URI's origin. |
| `state_mismatch`, `issuer_mismatch`, `invalid_request` | The response doesn't belong to this sign-in, didn't come from Rante Login, or is malformed. |
| `access_denied`, `login_required`, `consent_required`, … | Rante Login's own error. `access_denied` means the person cancelled. |
| `invalid_client` | The token endpoint refused the app's authentication. Check the key prefix, that the key is linked to the app and not expired, and that the private key matches. A browser-only app must not have a key. |
| `invalid_grant` | The code was used already, is older than 60 seconds, or doesn't match the redirect URI or the PKCE verifier. |
| `invalid_id_token` | The ID token failed a check; the message says which. |
| `invalid_token`, `userinfo_subject_mismatch`, `userinfo_failed` | Userinfo refused the access token, answered for another person, or failed. |
| `discovery_failed`, `network_error`, `invalid_token_response`, `token_request_failed` | Rante Login couldn't be reached, or answered in an unexpected way. |

## Example

[`examples/AspNetCore`](examples/AspNetCore) is a minimal-API website that signs people in three ways:

- the browser SDK's button, with FedCM in Chrome and Edge;
- the browser SDK's button with the redirect flow, elsewhere;
- a sign-in link that works without JavaScript, where the server starts the sign-in.

It keeps the person in cookie authentication, shows their claims and userinfo, and sends a Content Security Policy
that allows the browser SDK and FedCM.

```sh
cd examples/AspNetCore
RANTE_LOGIN_CLIENT_ID=… RANTE_LOGIN_KEY_PREFIX=rk_live_… RANTE_LOGIN_PRIVATE_KEY_FILE=../../private.pem dotnet run
```

Then open <http://localhost:3000>. In PowerShell, set the variables first, for example
`$env:RANTE_LOGIN_CLIENT_ID = '…'`.

| Variable | Default | Meaning |
|---|---|---|
| `RANTE_LOGIN_CLIENT_ID` | (required) | The app's Application (client) ID. |
| `RANTE_LOGIN_REDIRECT_URI` | `http://localhost:3000/auth/rante/callback` | Exactly as registered. The example handles the callback at its path, and listens on its port unless `ASPNETCORE_URLS` says otherwise. |
| `RANTE_LOGIN_KEY_PREFIX`, `RANTE_LOGIN_PRIVATE_KEY_FILE` | (none) | Server-side websites: the Signed JWT key's prefix, and its PEM private key. |
| `RANTE_LOGIN_SCOPE` | `openid profile email` | |
| `PORT`, `HOST` | the redirect URI's port, `127.0.0.1` | |

Open the site on the redirect URI's origin: browsers keep the sign-in cookies per host, so `localhost` and `127.0.0.1`
don't mix.

`appsettings.json` lowers ASP.NET Core's own logging to warnings, because its request log would record the
authorization code in the callback URL.

## Tests

```sh
dotnet test
```

The tests run offline, on .NET 8 and .NET 10. `tests/Rante.Login.Tests/LocalIdp.cs` is an `HttpMessageHandler` that
answers like Rante Login, in process:

- it publishes discovery and a JWKS, with keys generated for each run;
- it issues codes, and checks each token request: PKCE, the redirect URI, and the app's `private_key_jwt` assertion
  (algorithm, `kid`, `iss`, `sub`, `aud`, lifetime, a `jti` used once);
- it signs ID tokens, and serves userinfo.

The tests cover:

- successful sign-ins with RS256, ES256 and PKCE alone;
- every refusal: state, issuer, nonce, audience, `azp`, expiry, a foreign key, HS256 and `alg: none`;
- userinfo, configuration errors and network errors.

## Verified against Rante Login

On 9 November 2026 this version and its example signed in against the live `login.rante.com`, with a test app
registered in the Rante Portal and a real Rante account:

| Sign-in | App type | Client authentication |
|---|---|---|
| Redirect, started by the browser SDK's button | Server-side website | `private_key_jwt` with an RS256 key |
| Redirect, started by the server | Server-side website | `private_key_jwt` with an ES256 key |
| Redirect, started by the server | Browser-only website | none: PKCE alone |
| FedCM in Microsoft Edge | Browser-only website | none: the browser hands over the ID token |

In every run the server validated the ID token: the signature against the JWKS, `iss`, `aud` and `azp`, the nonce
and the expiry. The redirect runs also checked that:

- the browser SDK's cookies were cleared after a sign-in its button started;
- userinfo, called after the RS256 sign-in, returned the ID token's `sub`;
- signing out of the example worked.

The offline tests passed, and so did 21 checks against the running example (refusals, escaping and Origin checks).

## Production notes

- **HTTPS:** register an `https` redirect URI, and keep the state, nonce and verifier on the server.
- **Sessions:** use a shared `IDistributedCache` when the site runs on more than one server.
- **Logs:** don't log the redirect URI's query: it carries the one-time code.
- **Signing out:** signing out of your website doesn't sign the person out of Rante.
- **Redirect URIs:** Rante Login accepts only `https`, or `http://localhost` / `http://127.0.0.1` with the exact
  port.
- **Grants:** it has no refresh tokens and no device code flow.

## License

[MIT](LICENSE)
