using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Rante.Login.Tests;

/// <summary>
/// A local OpenID provider for the tests, shaped like Rante Login, answering in process (no network): discovery, JWKS,
/// token and userinfo. It issues codes that the tests hand it (standing in for the authorize step), checks each token
/// request (PKCE, redirect URI, client authentication, single-use assertions) and signs ID tokens with a key generated
/// for the run.
/// </summary>
public sealed class LocalIdp : HttpMessageHandler
{
    public const string Origin = "https://idp.test";
    public const string Issuer = Origin + "/common/v2.0";
    public const string AuthorizationEndpoint = Origin + "/common/oauth2/v2.0/authorize";
    public const string TokenEndpoint = Origin + "/common/oauth2/v2.0/token";
    public const string UserInfoEndpoint = Origin + "/common/oidc/v2.0/userinfo";
    public const string JwksUri = Origin + "/common/discovery/v2.0/keys";
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly List<RsaSecurityKey> _signingKeys = [];
    private readonly Dictionary<string, (string Type, Dictionary<string, SecurityKey> Keys)> _clients = [];
    private readonly Dictionary<string, IssuedCode> _codes = [];
    private readonly Dictionary<string, Dictionary<string, object>> _accessTokens = [];
    private readonly HashSet<string> _usedAssertions = [];
    private readonly JsonWebTokenHandler _handler = new();

    public LocalIdp()
    {
        AddSigningKey("test-key-1");
    }

    public string DiscoveryIssuer { get; set; } = Issuer;

    public List<(HttpMethod Method, string Path, Dictionary<string, string> Form, string? Authorization)> Requests { get; } = [];

    public (JsonWebToken Token, string Kid)? LastAssertion { get; private set; }

    public RsaSecurityKey AddSigningKey(string kid)
    {
        var key = new RsaSecurityKey(RSA.Create(2048)) { KeyId = kid };
        _signingKeys.Add(key);
        return key;
    }

    /// <summary>type is Web (keys: prefix to public key) or BrowserOnly.</summary>
    public void RegisterClient(string clientId, string type, Dictionary<string, SecurityKey>? keys = null) =>
        _clients[clientId] = (type, keys ?? []);

    /// <summary>Stands in for the authorize step: a code for these values.</summary>
    public string IssueCode(string clientId, string redirectUri, string codeChallenge, string nonce, Dictionary<string, object> claims)
    {
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _codes[code] = new IssuedCode(clientId, redirectUri, codeChallenge, nonce, claims);
        return code;
    }

    /// <summary>An ID token like Rante Login's. Override any claim (null removes it), or sign with another key.</summary>
    public string MintIdToken(Dictionary<string, object?> claims, SecurityKey? key = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "pairwise-subject-1",
            ["iat"] = now,
            ["exp"] = now + 600,
            ["auth_time"] = now,
        };
        foreach (var (name, value) in claims)
        {
            payload[name] = value;
        }

        var json = JsonSerializer.Serialize(payload.Where(p => p.Value is not null).ToDictionary(p => p.Key, p => p.Value));
        return _handler.CreateToken(json, new SigningCredentials(key ?? _signingKeys[0], SecurityAlgorithms.RsaSha256));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        var form = new Dictionary<string, string>();
        if (request.Content is not null)
        {
            var values = HttpUtility.ParseQueryString(await request.Content.ReadAsStringAsync(cancellationToken));
            foreach (var name in values.AllKeys.OfType<string>())
            {
                form[name] = values[name]!;
            }
        }

        Requests.Add((request.Method, path, form, request.Headers.Authorization?.ToString()));
        return (request.Method.Method, path) switch
        {
            ("GET", "/common/v2.0/.well-known/openid-configuration") => Json(HttpStatusCode.OK, new Dictionary<string, object>
            {
                ["issuer"] = DiscoveryIssuer,
                ["authorization_endpoint"] = AuthorizationEndpoint,
                ["token_endpoint"] = TokenEndpoint,
                ["userinfo_endpoint"] = UserInfoEndpoint,
                ["jwks_uri"] = JwksUri,
                ["response_types_supported"] = new[] { "code" },
                ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
                ["token_endpoint_auth_methods_supported"] = new[] { "private_key_jwt", "none" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
                ["authorization_response_iss_parameter_supported"] = true,
            }),
            ("GET", "/common/discovery/v2.0/keys") => Json(HttpStatusCode.OK, new { keys = _signingKeys.Select(Jwk).ToArray() }),
            ("POST", "/common/oauth2/v2.0/token") => await TokenAsync(form, request.Headers.Authorization is not null),
            ("GET", "/common/oidc/v2.0/userinfo") => UserInfo(request.Headers.Authorization),
            _ => Json(HttpStatusCode.NotFound, new { }),
        };
    }

    private async Task<HttpResponseMessage> TokenAsync(Dictionary<string, string> form, bool hasAuthorizationHeader)
    {
        HttpResponseMessage Refuse(HttpStatusCode status, string error) =>
            Json(status, new { error, error_description = $"test IdP: {error}" });

        var clientId = form.GetValueOrDefault("client_id") ?? "";
        if (!_clients.TryGetValue(clientId, out var client) || form.ContainsKey("client_secret") || hasAuthorizationHeader)
        {
            return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
        }

        if (client.Type == "Web")
        {
            var assertion = form.GetValueOrDefault("client_assertion");
            if (form.GetValueOrDefault("client_assertion_type") != AssertionType || string.IsNullOrEmpty(assertion))
            {
                return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
            }

            JsonWebToken unverified;
            try
            {
                unverified = new JsonWebToken(assertion);
            }
            catch (ArgumentException)
            {
                return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
            }

            if (!client.Keys.TryGetValue(unverified.Kid ?? "", out var key))
            {
                return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
            }

            var result = await _handler.ValidateTokenAsync(assertion, new TokenValidationParameters
            {
                IssuerSigningKey = key,
                ValidIssuer = clientId,
                ValidAudience = TokenEndpoint,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.EcdsaSha256],
                RequireExpirationTime = true,
            });
            var token = result.SecurityToken as JsonWebToken;
            if (!result.IsValid || token is null || token.Subject != clientId || string.IsNullOrEmpty(token.Id)
                || (token.ValidTo - token.IssuedAt) > TimeSpan.FromMinutes(5) || !_usedAssertions.Add(token.Id))
            {
                return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
            }

            LastAssertion = (token, unverified.Kid!);
        }
        else if (form.ContainsKey("client_assertion") || form.ContainsKey("client_assertion_type"))
        {
            return Refuse(HttpStatusCode.Unauthorized, "invalid_client");
        }

        var code = form.GetValueOrDefault("code") ?? "";
        _codes.Remove(code, out var issued);
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form.GetValueOrDefault("code_verifier") ?? "")));
        if (issued is null || issued.ClientId != clientId || issued.RedirectUri != form.GetValueOrDefault("redirect_uri")
            || issued.CodeChallenge != challenge)
        {
            return Refuse(HttpStatusCode.BadRequest, "invalid_grant");
        }

        var claims = new Dictionary<string, object?> { ["aud"] = clientId, ["azp"] = clientId, ["nonce"] = issued.Nonce };
        foreach (var (name, value) in issued.Claims)
        {
            claims[name] = value;
        }

        var accessToken = Guid.NewGuid().ToString();
        _accessTokens[accessToken] = new Dictionary<string, object> { ["sub"] = issued.Claims["sub"], ["name"] = issued.Claims["name"] };
        return Json(HttpStatusCode.OK, new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = 900,
            id_token = MintIdToken(claims),
            scope = "openid profile email",
        });
    }

    private HttpResponseMessage UserInfo(System.Net.Http.Headers.AuthenticationHeaderValue? authorization)
    {
        if (authorization?.Scheme != "Bearer" || authorization.Parameter is null || !_accessTokens.TryGetValue(authorization.Parameter, out var claims))
        {
            var refused = Json(HttpStatusCode.Unauthorized, new { });
            refused.Headers.Add("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            return refused;
        }

        return Json(HttpStatusCode.OK, claims);
    }

    private static Dictionary<string, string> Jwk(RsaSecurityKey key)
    {
        var parameters = key.Rsa.ExportParameters(false);
        return new Dictionary<string, string>
        {
            ["kty"] = "RSA",
            ["use"] = "sig",
            ["alg"] = "RS256",
            ["kid"] = key.KeyId,
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent),
        };
    }

    private static HttpResponseMessage Json(HttpStatusCode status, object body) => new(status)
    {
        Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
    };

    private sealed record IssuedCode(string ClientId, string RedirectUri, string CodeChallenge, string Nonce, Dictionary<string, object> Claims);
}
