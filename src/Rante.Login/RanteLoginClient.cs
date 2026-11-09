using System.Collections.Specialized;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Rante.Login;

/// <summary>
/// "Sign in with Rante" on a .NET server, built on Microsoft.IdentityModel.
/// </summary>
/// <remarks>
/// Rante Login is an OpenID Connect provider (issuer https://login.rante.com/common/v2.0) with the authorization code
/// flow with PKCE (S256), state, nonce and the <c>iss</c> response parameter (RFC 9207); client authentication by
/// <c>private_key_jwt</c> (RFC 7523) for server-side websites, or PKCE alone for browser-only websites; RS256 ID
/// tokens with a pairwise <c>sub</c>; and a userinfo endpoint. Create one client per app and keep it: it caches the
/// discovery document and the signing keys.
/// </remarks>
public sealed class RanteLoginClient
{
    /// <summary>https://login.rante.com/common/v2.0</summary>
    public const string DefaultIssuer = "https://login.rante.com/common/v2.0";

    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static readonly TimeSpan AssertionLifetime = TimeSpan.FromSeconds(60); // Rante Login accepts at most 5 minutes.
    private static readonly string[] Scopes = ["openid", "profile", "email", "phone", "address", "rante.organization"];
    private static readonly string[] Prompts = ["none", "login", "consent", "select_account"];
    private static readonly string[] CallbackParameters = ["code", "state", "iss", "error", "error_description"];
    private static readonly Regex GuidPattern = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.CultureInvariant);
    private static readonly Regex ErrorCodePattern = new("^[a-z0-9_]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly Regex NoncePattern = new("^[\\x21-\\x7e]{1,256}$", RegexOptions.CultureInvariant);

    private readonly HttpClient _http;
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _clockSkew;
    private readonly RanteLoginSigningKey? _signingKey;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _metadata;
    private readonly JsonWebTokenHandler _tokens = new();

    /// <summary>Creates a client for one app.</summary>
    /// <exception cref="RanteLoginException">With code <c>invalid_configuration</c> when a setting is wrong.</exception>
    public RanteLoginClient(RanteLoginOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ClientId = NormalizeClientId(options.ClientId);
        RedirectUri = NormalizeRedirectUri(options.RedirectUri);
        Scope = NormalizeScope(options.Scope);
        Issuer = NormalizeIssuer(options.Issuer);
        _signingKey = options.SigningKey;
        _timeout = options.Timeout;
        _clockSkew = options.ClockSkew;
        _http = options.HttpClient ?? new HttpClient(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AllowAutoRedirect = false,
        });
        // The discovery document and the signing keys (JWKS), cached, and fetched again when a token names a kid that
        // isn't known yet (key rotation), at most every 5 minutes.
        _metadata = new ConfigurationManager<OpenIdConnectConfiguration>($"{Issuer}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(_http) { RequireHttps = Issuer.StartsWith("https:", StringComparison.Ordinal) });
    }

    /// <summary>The app's Application (client) ID, in lower case.</summary>
    public string ClientId { get; }

    /// <summary>The redirect URI, with its scheme and host in lower case like the browser SDK sends it.</summary>
    public string RedirectUri { get; }

    /// <summary>The scopes requested.</summary>
    public string Scope { get; }

    /// <summary>The issuer.</summary>
    public string Issuer { get; }

    /// <summary><c>private_key_jwt</c> with the app's Signed JWT key, or <c>none</c> (PKCE alone).</summary>
    public string ClientAuthentication => _signingKey is null ? "none" : "private_key_jwt";

    /// <summary>
    /// Starts a sign-in on the server: the URL to send the browser to, and the values to keep (in the server-side
    /// session) until the browser comes back to the redirect URI.
    /// </summary>
    public async Task<AuthorizationRequest> CreateAuthorizationRequestAsync(AuthorizationRequestOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new AuthorizationRequestOptions();
        var nonce = options.Nonce is null ? RandomToken() : CheckNonce(options.Nonce);
        var prompt = CheckPrompt(options.Prompt);
        if (options.LoginHint is { Length: > 256 })
        {
            throw new RanteLoginException("invalid_request", "LoginHint must be at most 256 characters.");
        }

        if (options.MaxAge is < 0)
        {
            throw new RanteLoginException("invalid_request", "MaxAge must be a whole number of seconds.");
        }

        var configuration = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
        var state = RandomToken();
        var codeVerifier = RandomToken();
        var parameters = new List<KeyValuePair<string, string>>
        {
            new("client_id", ClientId),
            new("response_type", "code"),
            new("redirect_uri", RedirectUri),
            new("scope", Scope),
            new("state", state),
            new("nonce", nonce),
            new("code_challenge", Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)))),
            new("code_challenge_method", "S256"),
        };
        if (prompt is not null)
        {
            parameters.Add(new("prompt", prompt));
        }

        if (!string.IsNullOrEmpty(options.LoginHint))
        {
            parameters.Add(new("login_hint", options.LoginHint));
        }

        if (options.MaxAge is { } maxAge)
        {
            parameters.Add(new("max_age", maxAge.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        var endpoint = configuration.AuthorizationEndpoint;
        var query = string.Join('&', parameters.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var url = endpoint + (endpoint.Contains('?', StringComparison.Ordinal) ? "&" : "?") + query;
        return new AuthorizationRequest(url, state, nonce, codeVerifier);
    }

    /// <summary>
    /// Finishes a redirect sign-in at the redirect URI: checks the response against the values kept for it, exchanges
    /// the code and validates the ID token.
    /// </summary>
    /// <param name="callbackUrlOrQuery">The redirect URI as requested, or its query string (for example
    /// <c>Request.QueryString.Value</c>).</param>
    /// <param name="expected">What <see cref="CreateAuthorizationRequestAsync"/> returned, or
    /// <see cref="FromBrowserSdkCookies(IEnumerable{KeyValuePair{string, string}})"/> when the browser SDK started
    /// the sign-in.</param>
    /// <param name="cancellationToken">Cancels the calls to Rante Login.</param>
    public Task<RanteLoginResult> HandleCallbackAsync(string callbackUrlOrQuery, ExpectedTransaction? expected,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(callbackUrlOrQuery);
        var query = Regex.IsMatch(callbackUrlOrQuery, "^[A-Za-z][A-Za-z0-9+.-]*:")
            ? new Uri(callbackUrlOrQuery).Query
            : callbackUrlOrQuery;
        var values = HttpUtility.ParseQueryString(query.TrimStart('?'));
        return FinishAsync(name => values.GetValues(name) ?? [], expected, cancellationToken);
    }

    /// <summary>
    /// Finishes a redirect sign-in at the redirect URI, from the parsed query (for example ASP.NET Core's
    /// <c>Request.Query</c>).
    /// </summary>
    public Task<RanteLoginResult> HandleCallbackAsync(IEnumerable<KeyValuePair<string, StringValues>> query,
        ExpectedTransaction? expected, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        var values = query.ToDictionary(pair => pair.Key, pair => pair.Value.Where(v => v is not null).Select(v => v!).ToArray(),
            StringComparer.Ordinal);
        return FinishAsync(name => values.TryGetValue(name, out var found) ? found : [], expected, cancellationToken);
    }

    private async Task<RanteLoginResult> FinishAsync(Func<string, string[]> getValues, ExpectedTransaction? expected,
        CancellationToken cancellationToken)
    {
        var query = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var name in CallbackParameters)
        {
            var found = getValues(name);
            if (found.Length > 1)
            {
                throw new RanteLoginException("invalid_request", $"The response repeats {name}.");
            }

            query[name] = found.Length == 1 ? found[0] : null;
        }

        if (expected is null || string.IsNullOrEmpty(expected.State) || string.IsNullOrEmpty(expected.Nonce)
            || string.IsNullOrEmpty(expected.CodeVerifier))
        {
            throw new RanteLoginException("missing_transaction", "No sign-in is in progress for this browser, or it expired.");
        }

        if (!SafeEquals(query["state"], expected.State))
        {
            throw new RanteLoginException("state_mismatch", "The response does not belong to the sign-in this browser started.");
        }

        if (!string.Equals(query["iss"], Issuer, StringComparison.Ordinal))
        {
            throw new RanteLoginException("issuer_mismatch", "The response did not come from Rante Login.");
        }

        if (!string.IsNullOrEmpty(query["error"]))
        {
            var error = query["error"]!;
            var description = Clean(query["error_description"]);
            throw new RanteLoginException(ErrorCodePattern.IsMatch(error) ? error : "authorization_failed",
                description.Length > 0 ? description : error);
        }

        if (string.IsNullOrEmpty(query["code"]))
        {
            throw new RanteLoginException("invalid_request", "The response has no code.");
        }

        var tokens = await ExchangeCodeAsync(query["code"]!, expected.CodeVerifier, cancellationToken).ConfigureAwait(false);
        var idToken = await ValidateIdTokenAsync(tokens.IdToken, expected.Nonce, cancellationToken).ConfigureAwait(false);
        return new RanteLoginResult(idToken, tokens);
    }

    /// <summary>The token request: the code, the PKCE verifier and the app's client authentication.</summary>
    public async Task<TokenResponse> ExchangeCodeAsync(string code, string codeVerifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(codeVerifier))
        {
            throw new RanteLoginException("invalid_request", "The code and the code verifier are required.");
        }

        var configuration = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = RedirectUri,
            ["client_id"] = ClientId,
            ["code_verifier"] = codeVerifier,
        };
        if (_signingKey is not null)
        {
            form["client_assertion_type"] = AssertionType;
            form["client_assertion"] = ClientAssertion(configuration.TokenEndpoint, _signingKey);
        }

        // A browser-only app sends no credential at all: the PKCE verifier is its only proof.
        using var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var (status, body) = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (status != 200)
        {
            var error = GetString(body, "error");
            var description = Clean(GetString(body, "error_description"));
            throw new RanteLoginException(error is not null && ErrorCodePattern.IsMatch(error) ? error : "token_request_failed",
                description.Length > 0 ? description : $"The token endpoint answered {status}.", status);
        }

        var idToken = GetString(body, "id_token");
        var accessToken = GetString(body, "access_token");
        var tokenType = GetString(body, "token_type");
        if (string.IsNullOrEmpty(idToken) || string.IsNullOrEmpty(accessToken)
            || !string.Equals(tokenType, "Bearer", StringComparison.OrdinalIgnoreCase))
        {
            throw new RanteLoginException("invalid_token_response", "The token response has no ID token or no Bearer access token.");
        }

        int? expiresIn = body.ValueKind == JsonValueKind.Object && body.TryGetProperty("expires_in", out var e) && e.TryGetInt32(out var seconds)
            ? seconds
            : null;
        return new TokenResponse(accessToken, tokenType!, expiresIn, idToken, GetString(body, "scope"));
    }

    /// <summary>
    /// Validates an ID token before you trust it: the RS256 signature with the key its kid names in Rante Login's
    /// JWKS, <c>iss</c>, <c>aud</c> (and <c>azp</c>), <c>exp</c> (with clock skew), <c>iat</c>, <c>sub</c>, and the
    /// nonce you expect.
    /// </summary>
    public async Task<ValidatedIdToken> ValidateIdTokenAsync(string? idToken, string nonce, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            throw new RanteLoginException("invalid_request", "The expected nonce is required.");
        }

        if (string.IsNullOrEmpty(idToken))
        {
            throw new RanteLoginException("invalid_id_token", "The ID token is missing.");
        }

        await DiscoverAsync(cancellationToken).ConfigureAwait(false); // network failures surface here, not as invalid tokens
        var result = await _tokens.ValidateTokenAsync(idToken, new TokenValidationParameters
        {
            ConfigurationManager = _metadata, // the signature: RS256, with the JWKS key that the token's kid names
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidIssuer = Issuer,
            ValidAudience = ClientId,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = _clockSkew,
        }).ConfigureAwait(false);
        if (!result.IsValid)
        {
            throw new RanteLoginException("invalid_id_token",
                $"The ID token failed validation ({result.Exception?.GetType().Name ?? "invalid"}).", innerException: result.Exception);
        }

        var claims = result.Claims;
        if (!claims.TryGetValue("nonce", out var tokenNonce) || tokenNonce is not string nonceText || !SafeEquals(nonceText, nonce))
        {
            throw new RanteLoginException("invalid_id_token", "The ID token was issued for another sign-in (nonce).");
        }

        var multipleAudiences = claims.TryGetValue("aud", out var aud) && aud is System.Collections.IList { Count: > 1 };
        if (claims.TryGetValue("azp", out var azp)
                ? !string.Equals(azp as string, ClientId, StringComparison.Ordinal)
                : multipleAudiences)
        {
            throw new RanteLoginException("invalid_id_token", "The ID token was issued to another app (azp).");
        }

        if (!claims.TryGetValue("sub", out var sub) || sub is not string { Length: > 0 } subject || !claims.ContainsKey("iat"))
        {
            throw new RanteLoginException("invalid_id_token", "The ID token has no sub or no iat.");
        }

        return new ValidatedIdToken(subject, new Dictionary<string, object>(claims, StringComparer.Ordinal), result.ClaimsIdentity);
    }

    /// <summary>
    /// The person's claims from the userinfo endpoint, with the access token from the code exchange (15 minutes).
    /// Pass the ID token's <c>sub</c> as <paramref name="expectedSubject"/>: OpenID Connect requires that both match.
    /// </summary>
    public async Task<UserInfo> FetchUserInfoAsync(string accessToken, string? expectedSubject = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(accessToken))
        {
            throw new RanteLoginException("invalid_request", "An access token is required.");
        }

        var configuration = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
        using var request = new HttpRequestMessage(HttpMethod.Get, configuration.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var (status, body) = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (status == 401)
        {
            throw new RanteLoginException("invalid_token", "The access token was refused: it expired, or the person removed their consent.", 401);
        }

        var subject = GetString(body, "sub");
        if (status != 200 || string.IsNullOrEmpty(subject))
        {
            throw new RanteLoginException("userinfo_failed", $"The userinfo endpoint answered {status}.", status);
        }

        if (expectedSubject is not null && !string.Equals(subject, expectedSubject, StringComparison.Ordinal))
        {
            throw new RanteLoginException("userinfo_subject_mismatch", "The userinfo sub is not the ID token's sub.");
        }

        var claims = body.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone(), StringComparer.Ordinal);
        return new UserInfo(subject, claims);
    }

    /// <summary>
    /// The values the browser SDK (<c>serverSide: true</c>) kept for a redirect sign-in, from the request's cookies
    /// (for example ASP.NET Core's <c>Request.Cookies</c>). Null when any is missing. Clear the three cookies
    /// (<see cref="BrowserSdkCookies.All"/>) once read: each sign-in uses them once.
    /// </summary>
    public static ExpectedTransaction? FromBrowserSdkCookies(IEnumerable<KeyValuePair<string, string>> cookies)
    {
        string? state = null, nonce = null, verifier = null;
        foreach (var (name, value) in cookies ?? [])
        {
            switch (name)
            {
                case BrowserSdkCookies.State: state = value; break;
                case BrowserSdkCookies.Nonce: nonce = value; break;
                case BrowserSdkCookies.CodeVerifier: verifier = value; break;
            }
        }

        return !string.IsNullOrEmpty(state) && !string.IsNullOrEmpty(nonce) && !string.IsNullOrEmpty(verifier)
            ? new ExpectedTransaction(state, nonce, verifier)
            : null;
    }

    /// <summary>The same, from the Cookie header.</summary>
    public static ExpectedTransaction? FromBrowserSdkCookies(string? cookieHeader) =>
        FromBrowserSdkCookies((cookieHeader ?? "").Split(';')
            .Select(part => part.Split('=', 2))
            .Where(pair => pair.Length == 2)
            .Select(pair => new KeyValuePair<string, string>(pair[0].Trim(), pair[1].Trim())));

    // ------------------------------------------------------------------------------------------------ internals

    private async Task<OpenIdConnectConfiguration> DiscoverAsync(CancellationToken cancellationToken)
    {
        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await _metadata.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is InvalidOperationException or IOException or HttpRequestException)
        {
            var network = Inner(error).Any(e => e is HttpRequestException or TaskCanceledException or TimeoutException);
            throw new RanteLoginException(network ? "network_error" : "discovery_failed",
                network ? "Rante Login could not be reached." : "The discovery document could not be read.", innerException: error);
        }

        if (!string.Equals(configuration.Issuer, Issuer, StringComparison.Ordinal))
        {
            throw new RanteLoginException("discovery_failed", "The discovery document names another issuer.");
        }

        if (string.IsNullOrEmpty(configuration.AuthorizationEndpoint) || string.IsNullOrEmpty(configuration.TokenEndpoint)
            || string.IsNullOrEmpty(configuration.UserInfoEndpoint) || configuration.SigningKeys.Count == 0)
        {
            throw new RanteLoginException("discovery_failed", "The discovery document lacks an endpoint or the signing keys.");
        }

        return configuration;
    }

    // private_key_jwt (RFC 7523): a short-lived JWT signed with the app's private key.
    private string ClientAssertion(string tokenEndpoint, RanteLoginSigningKey signingKey)
    {
        var now = DateTime.UtcNow;
        return _tokens.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = ClientId, // iss and sub: the client ID
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = ClientId,
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString(), // Rante Login accepts each assertion once
            },
            Audience = tokenEndpoint, // aud: the token endpoint
            IssuedAt = now,
            NotBefore = now,
            Expires = now + AssertionLifetime,
            SigningCredentials = signingKey.Credentials, // kid: the key's prefix
        });
    }

    private async Task<(int Status, JsonElement Body)> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        try
        {
            using var response = await _http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            JsonElement body = default;
            try
            {
                using var document = JsonDocument.Parse(text);
                body = document.RootElement.Clone();
            }
            catch (JsonException)
            {
            }

            return ((int)response.StatusCode, body);
        }
        catch (Exception error) when (error is HttpRequestException || (error is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            throw new RanteLoginException("network_error", $"Rante Login could not be reached ({error.GetType().Name}).", innerException: error);
        }
    }

    private static string NormalizeClientId(string? value)
    {
        var clientId = (value ?? "").Trim().ToLowerInvariant();
        if (!GuidPattern.IsMatch(clientId))
        {
            throw Invalid("ClientId must be the app's Application (client) ID from the Rante Portal.");
        }

        return clientId;
    }

    // Rante Login matches redirect URIs exactly, and stores them with the scheme and host in lower case.
    private static string NormalizeRedirectUri(string? value)
    {
        var uri = Regex.Replace((value ?? "").Trim(), "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*", match => match.Value.ToLowerInvariant());
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed) || uri.Contains('#', StringComparison.Ordinal)
            || parsed.UserInfo.Length > 0 || uri.Length > 512
            || !(parsed.Scheme == "https" || (parsed.Scheme == "http" && parsed.Host is "localhost" or "127.0.0.1")))
        {
            throw Invalid("RedirectUri must be the absolute https URI registered on the app (http only for localhost or 127.0.0.1), without a fragment.");
        }

        return uri;
    }

    private static string NormalizeScope(string? value)
    {
        var parts = (value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (!parts.Contains("openid") || parts.Any(part => !Scopes.Contains(part)))
        {
            throw Invalid($"Scope must include openid and only these scopes: {string.Join(", ", Scopes)}.");
        }

        return string.Join(' ', parts.Distinct(StringComparer.Ordinal));
    }

    private static string NormalizeIssuer(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed) || parsed.Query.Length > 0 || parsed.Fragment.Length > 0
            || !(parsed.Scheme == "https" || (parsed.Scheme == "http" && parsed.Host is "localhost" or "127.0.0.1")))
        {
            throw Invalid("Issuer must be an https URL.");
        }

        return value!.TrimEnd('/');
    }

    private static string CheckNonce(string nonce) => NoncePattern.IsMatch(nonce)
        ? nonce
        : throw new RanteLoginException("invalid_request", "Nonce must be 1 to 256 printable ASCII characters without spaces.");

    private static string? CheckPrompt(string? prompt)
    {
        if (string.IsNullOrEmpty(prompt))
        {
            return null;
        }

        var parts = prompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || parts.Any(part => !Prompts.Contains(part)) || (parts.Contains("none") && parts.Length > 1))
        {
            throw new RanteLoginException("invalid_request", $"Prompt must be {string.Join(", ", Prompts)} (none alone).");
        }

        return string.Join(' ', parts);
    }

    private static string RandomToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    private static bool SafeEquals(string? a, string? b) =>
        a is not null && b is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string Clean(string? value) =>
        value is null ? "" : new string(value.Take(300).Select(c => char.IsControl(c) ? ' ' : c).ToArray());

    private static string? GetString(JsonElement body, string name) =>
        body.ValueKind == JsonValueKind.Object && body.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static IEnumerable<Exception> Inner(Exception error)
    {
        for (var current = error; current is not null; current = current.InnerException)
        {
            yield return current;
        }
    }

    private static RanteLoginException Invalid(string message) => new("invalid_configuration", message);
}
