using System.Security.Claims;
using System.Text.Json;

namespace Rante.Login;

/// <summary>Settings for a <see cref="RanteLoginClient"/>: one app.</summary>
public sealed class RanteLoginOptions
{
    /// <summary>The app's Application (client) ID.</summary>
    public required string ClientId { get; init; }

    /// <summary>Exactly as registered on the app.</summary>
    public required string RedirectUri { get; init; }

    /// <summary>Default <c>openid profile email</c>. Request only scopes whose information the app asks for.</summary>
    public string Scope { get; init; } = "openid profile email";

    /// <summary>
    /// Server-side websites: the Signed JWT key linked to the app. Without it the client authenticates with PKCE alone
    /// (browser-only websites).
    /// </summary>
    public RanteLoginSigningKey? SigningKey { get; init; }

    /// <summary>Default https://login.rante.com/common/v2.0.</summary>
    public string Issuer { get; init; } = RanteLoginClient.DefaultIssuer;

    /// <summary>The HttpClient for the calls to Rante Login. Default: one the client creates and keeps.</summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>The time each request to Rante Login may take. Default 10 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>The clock skew allowed for the ID token. Default 1 minute.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(1);
}

/// <summary>Options for <see cref="RanteLoginClient.CreateAuthorizationRequestAsync"/>.</summary>
public sealed class AuthorizationRequestOptions
{
    /// <summary>Your own nonce. Default: a random one.</summary>
    public string? Nonce { get; init; }

    /// <summary><c>none</c>, <c>login</c>, <c>consent</c> or <c>select_account</c>.</summary>
    public string? Prompt { get; init; }

    /// <summary>A suggested account, up to 256 characters.</summary>
    public string? LoginHint { get; init; }

    /// <summary>The maximum authentication age, in seconds.</summary>
    public int? MaxAge { get; init; }
}

/// <summary>
/// A sign-in the server starts: send the browser to <see cref="Url"/>, and keep <see cref="State"/>,
/// <see cref="Nonce"/> and <see cref="CodeVerifier"/> on the server until it comes back.
/// </summary>
public sealed record AuthorizationRequest(string Url, string State, string Nonce, string CodeVerifier)
{
    /// <summary>What the sign-in must match at the redirect URI.</summary>
    public ExpectedTransaction ToExpected() => new(State, Nonce, CodeVerifier);
}

/// <summary>What a sign-in must match at the redirect URI.</summary>
public sealed record ExpectedTransaction(string State, string Nonce, string CodeVerifier);

/// <summary>The token endpoint's answer.</summary>
public sealed record TokenResponse(string AccessToken, string TokenType, int? ExpiresIn, string IdToken, string? Scope);

/// <summary>A validated ID token.</summary>
public sealed class ValidatedIdToken
{
    internal ValidatedIdToken(string subject, IReadOnlyDictionary<string, object> claims, ClaimsIdentity identity)
    {
        Subject = subject;
        Claims = claims;
        Identity = identity;
    }

    /// <summary>The person's ID on your website: pairwise, so the same for your organization's apps and different for others.</summary>
    public string Subject { get; }

    /// <summary>The token's claims, by their JWT names.</summary>
    public IReadOnlyDictionary<string, object> Claims { get; }

    /// <summary>The claims as an identity (JWT claim names, not mapped), for example to sign in with cookie authentication.</summary>
    public ClaimsIdentity Identity { get; }
}

/// <summary>A finished sign-in: the validated ID token and the token response.</summary>
public sealed record RanteLoginResult(ValidatedIdToken IdToken, TokenResponse Tokens)
{
    /// <summary>The person's pairwise ID.</summary>
    public string Subject => IdToken.Subject;

    /// <summary>The ID token's claims.</summary>
    public IReadOnlyDictionary<string, object> Claims => IdToken.Claims;

    /// <summary>The access token for the userinfo endpoint (15 minutes).</summary>
    public string AccessToken => Tokens.AccessToken;
}

/// <summary>The userinfo endpoint's answer.</summary>
public sealed class UserInfo
{
    internal UserInfo(string subject, IReadOnlyDictionary<string, JsonElement> claims)
    {
        Subject = subject;
        Claims = claims;
    }

    /// <summary>The person's pairwise ID.</summary>
    public string Subject { get; }

    /// <summary>The claims, by name.</summary>
    public IReadOnlyDictionary<string, JsonElement> Claims { get; }
}

/// <summary>The cookies the Rante Login browser SDK writes with <c>serverSide: true</c> (SameSite=Lax, 10 minutes, Path=/).</summary>
public static class BrowserSdkCookies
{
    /// <summary>The PKCE verifier.</summary>
    public const string CodeVerifier = "rante_login_pkce";

    /// <summary>The state.</summary>
    public const string State = "rante_login_state";

    /// <summary>The nonce.</summary>
    public const string Nonce = "rante_login_nonce";

    /// <summary>All three, for clearing them once read.</summary>
    public static IReadOnlyList<string> All { get; } = [CodeVerifier, State, Nonce];
}

/// <summary>Every failure the SDK reports. <see cref="Code"/> is stable and safe to show; OAuth errors keep their own codes.</summary>
public sealed class RanteLoginException : Exception
{
    /// <summary>Creates the exception.</summary>
    public RanteLoginException(string code, string? message = null, int? status = null, Exception? innerException = null)
        : base(string.IsNullOrEmpty(message) ? code : message, innerException)
    {
        Code = code;
        Status = status;
    }

    /// <summary>For example <c>state_mismatch</c>, <c>invalid_grant</c> or <c>invalid_id_token</c>.</summary>
    public string Code { get; }

    /// <summary>The HTTP status, for errors that came from Rante Login.</summary>
    public int? Status { get; }
}
