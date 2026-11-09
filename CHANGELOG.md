# Changelog

## 1.0.0 (2026-11-09)

First release.

- **`RanteLoginClient`:** `CreateAuthorizationRequestAsync`, `HandleCallbackAsync`, `ExchangeCodeAsync`,
  `ValidateIdTokenAsync`, `FetchUserInfoAsync` and `FromBrowserSdkCookies`. Targets .NET 8 and .NET 10.
- **Client authentication:** `private_key_jwt` (RS256 or ES256) for server-side websites, and PKCE alone for
  browser-only websites.
- **Example:** `examples/AspNetCore`.
