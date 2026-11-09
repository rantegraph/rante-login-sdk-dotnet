using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Rante.Login.Tests;

public sealed class IdpFixture
{
    public const string WebClient = "11111111-2222-4333-8444-555555555555";
    public const string BrowserClient = "66666666-7777-4888-9999-aaaaaaaaaaaa";
    // The fake key prefixes, split so secret scanners don't take them for Stripe restricted keys (rk_live_ + 24 characters).
    public const string RsaPrefix = "rk_live_" + "0123456789abcdef01234567";
    public const string EcPrefix = "rk_live_" + "89abcdef0123456789abcdef";

    public IdpFixture()
    {
        Idp.RegisterClient(WebClient, "Web", new Dictionary<string, SecurityKey>
        {
            [RsaPrefix] = new RsaSecurityKey(Rsa.ExportParameters(false)),
            [EcPrefix] = new ECDsaSecurityKey(ECDsa.Create(Ec.ExportParameters(false))),
        });
        Idp.RegisterClient(BrowserClient, "BrowserOnly");
    }

    public LocalIdp Idp { get; } = new();
    public RSA Rsa { get; } = RSA.Create(2048);
    public ECDsa Ec { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
}

public sealed class RanteLoginClientTests(IdpFixture fixture) : IClassFixture<IdpFixture>
{
    private const string RedirectUri = "http://localhost:3000/auth/rante/callback";
    private const string Nonce = "expected-nonce";
    private LocalIdp Idp => fixture.Idp;

    private RanteLoginClient Client(string clientId = IdpFixture.WebClient, RanteLoginSigningKey? signingKey = null, bool browserOnly = false) =>
        new(new RanteLoginOptions
        {
            ClientId = clientId,
            RedirectUri = RedirectUri,
            Issuer = LocalIdp.Issuer,
            HttpClient = new HttpClient(Idp, disposeHandler: false),
            SigningKey = browserOnly ? null : signingKey ?? RanteLoginSigningKey.FromRsa(IdpFixture.RsaPrefix, fixture.Rsa),
        });

    // The authorize step, as the test IdP sees it: a code bound to the request's PKCE challenge and nonce.
    private string Authorize(AuthorizationRequest request, string clientId)
    {
        var query = HttpUtility.ParseQueryString(new Uri(request.Url).Query);
        return Idp.IssueCode(clientId, query["redirect_uri"]!, query["code_challenge"]!, query["nonce"]!,
            new Dictionary<string, object> { ["sub"] = "pairwise-subject-1", ["name"] = "Test Person" });
    }

    private static async Task<RanteLoginException> Fails(string code, Func<Task> call)
    {
        var error = await Assert.ThrowsAsync<RanteLoginException>(call);
        Assert.True(error.Code == code, $"expected {code}, got {error.Code}: {error.Message}");
        return error;
    }

    private string Callback(string? code, string? state, string? iss = LocalIdp.Issuer) =>
        "?" + string.Join('&', new[] { ("code", code), ("state", state), ("iss", iss) }
            .Where(p => p.Item2 is not null).Select(p => $"{p.Item1}={Uri.EscapeDataString(p.Item2!)}"));

    [Fact]
    public async Task CreateAuthorizationRequest_builds_the_url_with_PKCE_S256_state_and_nonce()
    {
        var request = await Client().CreateAuthorizationRequestAsync();
        var url = new Uri(request.Url);
        Assert.Equal(LocalIdp.AuthorizationEndpoint, url.GetLeftPart(UriPartial.Path));
        var query = HttpUtility.ParseQueryString(url.Query);
        Assert.Equal(["client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"],
            query.AllKeys.OfType<string>().Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(IdpFixture.WebClient, query["client_id"]);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal(RedirectUri, query["redirect_uri"]);
        Assert.Equal("openid profile email", query["scope"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(request.CodeVerifier))), query["code_challenge"]);
        Assert.Equal(request.State, query["state"]);
        Assert.Equal(request.Nonce, query["nonce"]);
        Assert.Equal(43, request.CodeVerifier.Length);
        var other = await Client().CreateAuthorizationRequestAsync();
        Assert.NotEqual(request.State, other.State);
        Assert.NotEqual(request.Nonce, other.Nonce);
        Assert.NotEqual(request.CodeVerifier, other.CodeVerifier);
    }

    [Fact]
    public async Task CreateAuthorizationRequest_passes_options_and_refuses_bad_ones()
    {
        var client = Client();
        var request = await client.CreateAuthorizationRequestAsync(new AuthorizationRequestOptions
        {
            Nonce = "server-nonce-1",
            Prompt = "login",
            LoginHint = "person@example.com",
            MaxAge = 0,
        });
        var query = HttpUtility.ParseQueryString(new Uri(request.Url).Query);
        Assert.Equal("server-nonce-1", request.Nonce);
        Assert.Equal("server-nonce-1", query["nonce"]);
        Assert.Equal("login", query["prompt"]);
        Assert.Equal("person@example.com", query["login_hint"]);
        Assert.Equal("0", query["max_age"]);
        await Fails("invalid_request", () => client.CreateAuthorizationRequestAsync(new AuthorizationRequestOptions { Nonce = "has space" }));
        await Fails("invalid_request", () => client.CreateAuthorizationRequestAsync(new AuthorizationRequestOptions { Prompt = "none login" }));
        await Fails("invalid_request", () => client.CreateAuthorizationRequestAsync(new AuthorizationRequestOptions { Prompt = "always" }));
        await Fails("invalid_request", () => client.CreateAuthorizationRequestAsync(new AuthorizationRequestOptions { MaxAge = -1 }));
    }

    [Fact]
    public async Task HandleCallback_server_side_website_signs_in_with_a_private_key_jwt_RS256_assertion()
    {
        var client = Client();
        Assert.Equal("private_key_jwt", client.ClientAuthentication);
        var request = await client.CreateAuthorizationRequestAsync();
        var code = Authorize(request, IdpFixture.WebClient);
        var result = await client.HandleCallbackAsync(RedirectUri + Callback(code, request.State), request.ToExpected());
        Assert.Equal("pairwise-subject-1", result.Subject);
        Assert.Equal("Test Person", result.Claims["name"]);
        Assert.Equal(request.Nonce, result.Claims["nonce"]);
        Assert.Equal("Bearer", result.Tokens.TokenType);
        Assert.False(string.IsNullOrEmpty(result.AccessToken));

        var form = Idp.Requests.Last(r => r.Path.EndsWith("/token", StringComparison.Ordinal)).Form;
        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal(RedirectUri, form["redirect_uri"]);
        Assert.Equal(IdpFixture.WebClient, form["client_id"]);
        Assert.Equal(request.CodeVerifier, form["code_verifier"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form["client_assertion_type"]);
        var (assertion, kid) = Idp.LastAssertion!.Value;
        Assert.Equal("RS256", assertion.Alg);
        Assert.Equal(IdpFixture.RsaPrefix, kid);
        Assert.Equal(IdpFixture.WebClient, assertion.Issuer);
        Assert.Equal(IdpFixture.WebClient, assertion.Subject);
        Assert.Equal([LocalIdp.TokenEndpoint], assertion.Audiences.ToArray());
        Assert.True(assertion.ValidTo - assertion.IssuedAt <= TimeSpan.FromMinutes(5));
        Assert.True(Guid.TryParse(assertion.Id, out _));
    }

    [Fact]
    public async Task HandleCallback_ES256_keys_sign_ES256_assertions()
    {
        var client = Client(signingKey: RanteLoginSigningKey.FromECDsa(IdpFixture.EcPrefix, fixture.Ec));
        var request = await client.CreateAuthorizationRequestAsync();
        var result = await client.HandleCallbackAsync(Callback(Authorize(request, IdpFixture.WebClient), request.State), request.ToExpected());
        Assert.Equal("pairwise-subject-1", result.Subject);
        Assert.Equal("ES256", Idp.LastAssertion!.Value.Token.Alg);
        Assert.Equal(IdpFixture.EcPrefix, Idp.LastAssertion!.Value.Kid);
    }

    [Fact]
    public async Task HandleCallback_browser_only_website_sends_no_client_credential()
    {
        var client = Client(IdpFixture.BrowserClient, browserOnly: true);
        Assert.Equal("none", client.ClientAuthentication);
        var request = await client.CreateAuthorizationRequestAsync();
        var query = new Dictionary<string, StringValues>
        {
            ["code"] = Authorize(request, IdpFixture.BrowserClient),
            ["state"] = request.State,
            ["iss"] = LocalIdp.Issuer,
        };
        var result = await client.HandleCallbackAsync(query, new ExpectedTransaction(request.State, request.Nonce, request.CodeVerifier));
        Assert.Equal(IdpFixture.BrowserClient, result.Claims["aud"]);
        var form = Idp.Requests.Last(r => r.Path.EndsWith("/token", StringComparison.Ordinal)).Form;
        Assert.False(form.ContainsKey("client_assertion"));
        Assert.False(form.ContainsKey("client_assertion_type"));
        Assert.False(form.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task HandleCallback_refuses_bad_responses_before_any_token_request()
    {
        var client = Client();
        var request = await client.CreateAuthorizationRequestAsync();
        var code = Authorize(request, IdpFixture.WebClient);
        var before = Idp.Requests.Count;
        await Fails("state_mismatch", () => client.HandleCallbackAsync(Callback(code, "another"), request.ToExpected()));
        await Fails("issuer_mismatch", () => client.HandleCallbackAsync(Callback(code, request.State, iss: null), request.ToExpected()));
        await Fails("issuer_mismatch", () => client.HandleCallbackAsync(Callback(code, request.State, "https://login.example.com/common/v2.0"), request.ToExpected()));
        await Fails("invalid_request", () => client.HandleCallbackAsync(Callback(code, request.State) + "&state=" + request.State, request.ToExpected()));
        await Fails("missing_transaction", () => client.HandleCallbackAsync(Callback(code, request.State), null));
        await Fails("missing_transaction", () => client.HandleCallbackAsync(Callback(code, request.State), new ExpectedTransaction(request.State, "", "")));
        await Fails("invalid_request", () => client.HandleCallbackAsync(Callback(null, request.State), request.ToExpected()));
        Assert.Equal(before, Idp.Requests.Count);
    }

    [Fact]
    public async Task HandleCallback_reports_the_providers_error()
    {
        var client = Client();
        var request = await client.CreateAuthorizationRequestAsync();
        var query = $"?error=access_denied&error_description={Uri.EscapeDataString("The person cancelled the sign-in.")}&state={request.State}&iss={Uri.EscapeDataString(LocalIdp.Issuer)}";
        var error = await Fails("access_denied", () => client.HandleCallbackAsync(query, request.ToExpected()));
        Assert.Equal("The person cancelled the sign-in.", error.Message);
    }

    [Fact]
    public async Task HandleCallback_token_endpoint_errors_keep_their_code_and_status()
    {
        var client = Client();
        var request = await client.CreateAuthorizationRequestAsync();
        var callback = Callback(Authorize(request, IdpFixture.WebClient), request.State);
        await client.HandleCallbackAsync(callback, request.ToExpected());
        var error = await Fails("invalid_grant", () => client.HandleCallbackAsync(callback, request.ToExpected()));
        Assert.Equal(400, error.Status);
    }

    [Fact]
    public async Task HandleCallback_a_key_that_is_not_linked_to_the_app_gets_invalid_client()
    {
        var client = Client(signingKey: RanteLoginSigningKey.FromRsa("rk_live_" + new string('f', 24), RSA.Create(2048)));
        var request = await client.CreateAuthorizationRequestAsync();
        var error = await Fails("invalid_client", () => client.HandleCallbackAsync(Callback(Authorize(request, IdpFixture.WebClient), request.State), request.ToExpected()));
        Assert.Equal(401, error.Status);
    }

    private string Valid(Dictionary<string, object?>? overrides = null)
    {
        var claims = new Dictionary<string, object?> { ["aud"] = IdpFixture.WebClient, ["azp"] = IdpFixture.WebClient, ["nonce"] = Nonce };
        foreach (var (name, value) in overrides ?? [])
        {
            claims[name] = value;
        }

        return Idp.MintIdToken(claims);
    }

    [Fact]
    public async Task ValidateIdToken_accepts_a_valid_token()
    {
        var token = await Client().ValidateIdTokenAsync(Valid(new() { ["name"] = "Test Person" }), Nonce);
        Assert.Equal("pairwise-subject-1", token.Subject);
        Assert.Equal("Test Person", token.Claims["name"]);
        Assert.Equal("pairwise-subject-1", token.Identity.FindFirst("sub")?.Value);
    }

    [Fact]
    public async Task ValidateIdToken_refuses_tokens_that_fail_any_check()
    {
        var client = Client();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var stranger = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "test-key-1" };
        var unknownKid = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "not-a-rante-key" };
        var body = new Dictionary<string, object?> { ["iss"] = LocalIdp.Issuer, ["sub"] = "s", ["aud"] = IdpFixture.WebClient, ["azp"] = IdpFixture.WebClient, ["iat"] = now, ["exp"] = now + 600, ["nonce"] = Nonce };
        var hs256 = new JsonWebTokenHandler().CreateToken(System.Text.Json.JsonSerializer.Serialize(body),
            new SigningCredentials(new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32)) { KeyId = "test-key-1" }, SecurityAlgorithms.HmacSha256));
        static string B64(string json) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(json));
        var cases = new Dictionary<string, string>
        {
            ["another key, same kid"] = Idp.MintIdToken(new() { ["aud"] = IdpFixture.WebClient, ["nonce"] = Nonce }, stranger),
            ["unknown kid"] = Idp.MintIdToken(new() { ["aud"] = IdpFixture.WebClient, ["nonce"] = Nonce }, unknownKid),
            ["another issuer"] = Valid(new() { ["iss"] = "https://login.example.com/common/v2.0" }),
            ["another audience"] = Valid(new() { ["aud"] = "99999999-2222-4333-8444-555555555555", ["azp"] = null }),
            ["another azp"] = Valid(new() { ["azp"] = "99999999-2222-4333-8444-555555555555" }),
            ["expired"] = Valid(new() { ["iat"] = now - 1200, ["exp"] = now - 600 }),
            ["another nonce"] = Valid(new() { ["nonce"] = "other-nonce" }),
            ["no nonce"] = Valid(new() { ["nonce"] = null }),
            ["no sub"] = Valid(new() { ["sub"] = null }),
            ["HS256"] = hs256,
            ["alg none"] = $"{B64("{\"alg\":\"none\",\"typ\":\"JWT\"}")}.{B64(System.Text.Json.JsonSerializer.Serialize(body))}.",
            ["not a JWT"] = "not-a-jwt",
        };
        foreach (var (name, token) in cases)
        {
            var error = await Assert.ThrowsAsync<RanteLoginException>(() => client.ValidateIdTokenAsync(token, Nonce));
            Assert.True(error.Code == "invalid_id_token", $"{name}: {error.Code} {error.Message}");
        }

        await Fails("invalid_request", () => client.ValidateIdTokenAsync(Valid(), ""));
    }

    [Fact]
    public async Task ValidateIdToken_allows_a_minute_of_clock_skew()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await Client().ValidateIdTokenAsync(Valid(new() { ["iat"] = now - 630, ["exp"] = now - 30 }), Nonce);
    }

    [Fact]
    public async Task ValidateIdToken_uses_a_key_that_Rante_Login_adds_later()
    {
        var added = Idp.AddSigningKey("test-key-2");
        var token = Idp.MintIdToken(new() { ["aud"] = IdpFixture.WebClient, ["nonce"] = Nonce }, added);
        Assert.Equal("pairwise-subject-1", (await Client().ValidateIdTokenAsync(token, Nonce)).Subject);
    }

    [Fact]
    public async Task FetchUserInfo_returns_the_claims_and_checks_the_sub()
    {
        var client = Client();
        var request = await client.CreateAuthorizationRequestAsync();
        var result = await client.HandleCallbackAsync(Callback(Authorize(request, IdpFixture.WebClient), request.State), request.ToExpected());
        var userinfo = await client.FetchUserInfoAsync(result.AccessToken, result.Subject);
        Assert.Equal("pairwise-subject-1", userinfo.Subject);
        Assert.Equal("Test Person", userinfo.Claims["name"].GetString());
        Assert.Equal($"Bearer {result.AccessToken}", Idp.Requests.Last(r => r.Path.EndsWith("/userinfo", StringComparison.Ordinal)).Authorization);
        await Fails("userinfo_subject_mismatch", () => client.FetchUserInfoAsync(result.AccessToken, "someone-else"));
        var error = await Fails("invalid_token", () => client.FetchUserInfoAsync("expired-or-unknown"));
        Assert.Equal(401, error.Status);
    }

    [Fact]
    public void FromBrowserSdkCookies_reads_the_three_cookies()
    {
        var verifier = new string('v', 43);
        var expected = new ExpectedTransaction("s1", "n1", verifier);
        Assert.Equal(expected, RanteLoginClient.FromBrowserSdkCookies(new Dictionary<string, string>
        {
            [BrowserSdkCookies.State] = "s1",
            [BrowserSdkCookies.Nonce] = "n1",
            [BrowserSdkCookies.CodeVerifier] = verifier,
        }));
        Assert.Equal(expected, RanteLoginClient.FromBrowserSdkCookies($"other=1; rante_login_pkce={verifier}; rante_login_state=s1; rante_login_nonce=n1"));
        Assert.Null(RanteLoginClient.FromBrowserSdkCookies(new Dictionary<string, string> { [BrowserSdkCookies.State] = "s1" }));
        Assert.Null(RanteLoginClient.FromBrowserSdkCookies((string?)null));
    }

    [Fact]
    public void Configuration_refuses_bad_settings()
    {
        RanteLoginOptions Options(string clientId = IdpFixture.WebClient, string redirectUri = RedirectUri, string scope = "openid profile email",
            string issuer = RanteLoginClient.DefaultIssuer) => new() { ClientId = clientId, RedirectUri = redirectUri, Scope = scope, Issuer = issuer };

        var bad = new Dictionary<string, Func<object>>
        {
            ["client ID"] = () => new RanteLoginClient(Options(clientId: "my-app")),
            ["http redirect URI"] = () => new RanteLoginClient(Options(redirectUri: "http://shop.example.com/callback")),
            ["redirect URI with a fragment"] = () => new RanteLoginClient(Options(redirectUri: "https://shop.example.com/callback#x")),
            ["scope without openid"] = () => new RanteLoginClient(Options(scope: "profile email")),
            ["unknown scope"] = () => new RanteLoginClient(Options(scope: "openid offline_access")),
            ["http issuer"] = () => new RanteLoginClient(Options(issuer: "http://login.example.com/common/v2.0")),
            ["key prefix"] = () => RanteLoginSigningKey.FromRsa("my-key", fixture.Rsa),
            ["RSA 1024"] = () => RanteLoginSigningKey.FromRsa(IdpFixture.RsaPrefix, RSA.Create(1024)),
            ["EC P-384"] = () => RanteLoginSigningKey.FromECDsa(IdpFixture.RsaPrefix, ECDsa.Create(ECCurve.NamedCurves.nistP384)),
            ["a public key"] = () => RanteLoginSigningKey.FromPem(IdpFixture.RsaPrefix, fixture.Rsa.ExportSubjectPublicKeyInfoPem()),
        };
        foreach (var (name, create) in bad)
        {
            var error = Assert.Throws<RanteLoginException>(create);
            Assert.True(error.Code == "invalid_configuration", name);
        }
    }

    [Fact]
    public void Configuration_reads_PEM_keys_and_normalizes_like_the_browser_SDK()
    {
        Assert.Equal("RS256", RanteLoginSigningKey.FromPem(IdpFixture.RsaPrefix, fixture.Rsa.ExportPkcs8PrivateKeyPem()).Algorithm);
        Assert.Equal("ES256", RanteLoginSigningKey.FromPem(IdpFixture.EcPrefix, fixture.Ec.ExportPkcs8PrivateKeyPem()).Algorithm);
        var client = new RanteLoginClient(new RanteLoginOptions { ClientId = IdpFixture.WebClient.ToUpperInvariant(), RedirectUri = "HTTPS://Shop.Example.com/Auth/Callback" });
        Assert.Equal(IdpFixture.WebClient, client.ClientId);
        Assert.Equal("https://shop.example.com/Auth/Callback", client.RedirectUri);
        Assert.Equal("https://login.rante.com/common/v2.0", client.Issuer);
    }

    [Fact]
    public async Task Discovery_that_names_another_issuer_is_refused()
    {
        Idp.DiscoveryIssuer = "https://login.example.com/common/v2.0";
        try
        {
            await Fails("discovery_failed", () => Client().CreateAuthorizationRequestAsync());
        }
        finally
        {
            Idp.DiscoveryIssuer = LocalIdp.Issuer;
        }
    }

    [Fact]
    public async Task An_unreachable_provider_is_a_network_error()
    {
        var client = new RanteLoginClient(new RanteLoginOptions
        {
            ClientId = IdpFixture.WebClient,
            RedirectUri = RedirectUri,
            Issuer = LocalIdp.Issuer,
            HttpClient = new HttpClient(new Unreachable()),
        });
        await Fails("network_error", () => client.CreateAuthorizationRequestAsync());
    }

    private sealed class Unreachable : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("No connection could be made.");
    }
}
