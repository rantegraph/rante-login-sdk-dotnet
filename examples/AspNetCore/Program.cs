// Sign in with Rante: an ASP.NET Core website that signs people in with the Rante Login SDK for .NET.
//
// Three ways in, all finished and checked on this server:
// - "Sign in with Rante" button (wwwroot/signin.js): the browser SDK with serverSide: true. In Chrome and Edge it uses
//   FedCM and posts the ID token to /auth/rante/fedcm; elsewhere it redirects, and the code comes back to the
//   redirect URI with the SDK's rante_login_* cookies.
// - "Sign in without JavaScript" link: /auth/rante/sign-in builds the authorize request here
//   (CreateAuthorizationRequestAsync) and keeps its state, nonce and PKCE verifier in the session.
// - Either redirect ends at the redirect URI, where HandleCallbackAsync exchanges the code (private_key_jwt or PKCE
//   alone) and validates the ID token.

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Rante.Login;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

RanteLoginClient rante;
try
{
    var keyPrefix = configuration["RANTE_LOGIN_KEY_PREFIX"] ?? "";
    var keyFile = configuration["RANTE_LOGIN_PRIVATE_KEY_FILE"] ?? "";
    if (keyPrefix.Length > 0 != keyFile.Length > 0)
    {
        throw new RanteLoginException("invalid_configuration",
            "Set both RANTE_LOGIN_KEY_PREFIX and RANTE_LOGIN_PRIVATE_KEY_FILE (a server-side website), or neither (browser-only).");
    }

    rante = new RanteLoginClient(new RanteLoginOptions
    {
        ClientId = configuration["RANTE_LOGIN_CLIENT_ID"] ?? "",
        RedirectUri = configuration["RANTE_LOGIN_REDIRECT_URI"] is { Length: > 0 } redirectUri ? redirectUri : "http://localhost:3000/auth/rante/callback",
        Scope = configuration["RANTE_LOGIN_SCOPE"] is { Length: > 0 } scope ? scope : "openid profile email",
        SigningKey = keyFile.Length > 0 ? RanteLoginSigningKey.FromPem(keyPrefix, File.ReadAllText(keyFile)) : null,
    });
}
catch (Exception error) when (error is RanteLoginException or IOException)
{
    Console.Error.WriteLine(error.Message);
    return 1;
}

var redirect = new Uri(rante.RedirectUri);
var siteOrigin = redirect.GetLeftPart(UriPartial.Authority);
var callbackPath = redirect.AbsolutePath;
if (callbackPath is "/" or "/auth/rante/sign-in" or "/auth/rante/fedcm" or "/auth/sign-out" or "/userinfo")
{
    Console.Error.WriteLine("Give RANTE_LOGIN_REDIRECT_URI a path of its own, for example /auth/rante/callback.");
    return 1;
}

if (string.IsNullOrEmpty(configuration["urls"]))
{
    var port = int.TryParse(configuration["PORT"], out var p) ? p : redirect.Port;
    builder.WebHost.UseUrls($"http://{(configuration["HOST"] is { Length: > 0 } host ? host : "127.0.0.1")}:{port}");
}

builder.Services.AddSingleton(rante);
// The server-started sign-in and the FedCM nonce live in the server-side session.
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.Cookie.Name = "rante_aspnetcore_session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.IsEssential = true;
    options.IdleTimeout = TimeSpan.FromHours(1);
});
// The person who signed in, in an encrypted cookie.
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "rante_aspnetcore_auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = false;
    });

var app = builder.Build();

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.ContentSecurityPolicy = string.Join("; ",
        "default-src 'self'",
        "script-src 'self' https://login.rante.com", // the browser SDK, pinned by its integrity hash
        "connect-src 'self' https://login.rante.com", // FedCM fetches the identity provider's configuration
        "img-src 'self' data:",
        "style-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'");
    headers["Referrer-Policy"] = "same-origin";
    headers.XContentTypeOptions = "nosniff";
    await next();
});
app.UseStaticFiles();
app.UseSession();
app.UseAuthentication();

app.MapGet("/", (HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";
    if (context.User.Identity?.IsAuthenticated == true)
    {
        return Pages.Html(Pages.SignedIn(context.User));
    }

    // FedCM hands the ID token to the page, so its nonce must be one the page can't choose: issue it here and keep it
    // in the session. The browser SDK sends the same nonce in its redirect flow.
    var nonce = context.Session.GetString(Keys.Nonce);
    if (nonce is null)
    {
        nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        context.Session.SetString(Keys.Nonce, nonce);
    }

    return Pages.Html(Pages.SignIn(rante, nonce));
});

// The server starts the sign-in: no JavaScript needed.
app.MapGet("/auth/rante/sign-in", async (HttpContext context, ILogger<Program> logger) =>
{
    try
    {
        var request = await rante.CreateAuthorizationRequestAsync(cancellationToken: context.RequestAborted);
        context.Session.SetString(Keys.Request, JsonSerializer.Serialize(request.ToExpected()));
        return Results.Redirect(request.Url);
    }
    catch (RanteLoginException error)
    {
        return Pages.Error(error, logger);
    }
});

// The redirect URI: Rante Login comes back with ?code=...&state=...&iss=... (or ?error=...).
app.MapGet(callbackPath, async (HttpContext context, ILogger<Program> logger) =>
{
    // A sign-in this server started is in the session; one the browser SDK started is in its cookies. Both are used once.
    var started = context.Session.GetString(Keys.Request) is { } json ? JsonSerializer.Deserialize<ExpectedTransaction>(json) : null;
    context.Session.Remove(Keys.Request);
    var fromBrowser = RanteLoginClient.FromBrowserSdkCookies(context.Request.Cookies);
    foreach (var name in BrowserSdkCookies.All)
    {
        context.Response.Cookies.Delete(name, new CookieOptions { Path = "/" });
    }

    var byServer = started is not null && started.State == context.Request.Query["state"];
    try
    {
        var result = await rante.HandleCallbackAsync(context.Request.Query, byServer ? started : fromBrowser ?? started, context.RequestAborted);
        await StartSessionAsync(context, result.IdToken, result.AccessToken,
            $"{(byServer ? "Redirect started by the server" : "Redirect started by the browser SDK")}, {rante.ClientAuthentication}");
        return Results.Redirect("/");
    }
    catch (RanteLoginException error)
    {
        return Pages.Error(error, logger);
    }
});

// FedCM: the page posts the ID token the browser's account dialog returned.
app.MapPost("/auth/rante/fedcm", async (HttpContext context, ILogger<Program> logger) =>
{
    if (context.Request.Headers.Origin.Count != 1 || context.Request.Headers.Origin[0] != siteOrigin)
    {
        return Results.Json(new { error = "origin_not_allowed" }, statusCode: StatusCodes.Status403Forbidden);
    }

    try
    {
        var nonce = context.Session.GetString(Keys.Nonce)
            ?? throw new RanteLoginException("missing_transaction", "This browser session has no sign-in nonce. Reload the page.");
        string? idToken = null;
        if (context.Request.HasJsonContentType() && context.Request.ContentLength is null or <= 16 * 1024)
        {
            try
            {
                idToken = (await context.Request.ReadFromJsonAsync<FedCmSignIn>(context.RequestAborted))?.IdToken;
            }
            catch (JsonException)
            {
            }
        }

        var token = await rante.ValidateIdTokenAsync(idToken, nonce, context.RequestAborted);
        await StartSessionAsync(context, token, null, "FedCM");
        return Results.NoContent();
    }
    catch (RanteLoginException error)
    {
        logger.LogWarning("FedCM sign-in failed: {Code}: {Message}", error.Code, error.Message);
        return Results.Json(new { error = error.Code }, statusCode: StatusCodes.Status400BadRequest);
    }
});

// The person's claims from Rante Login's userinfo endpoint, with the access token from the code exchange (15 minutes).
app.MapGet("/userinfo", async (HttpContext context, ILogger<Program> logger) =>
{
    context.Response.Headers.CacheControl = "no-store";
    if (context.User.Identity?.IsAuthenticated != true)
    {
        return Results.Redirect("/");
    }

    var accessToken = (await context.AuthenticateAsync()).Properties?.GetTokenValue("access_token");
    if (accessToken is null)
    {
        return Pages.Html(Pages.Message("Userinfo", "FedCM sign-ins return only an ID token, so there is no access token to call userinfo with."));
    }

    try
    {
        var userinfo = await rante.FetchUserInfoAsync(accessToken, context.User.FindFirst("sub")?.Value, context.RequestAborted);
        return Pages.Html(Pages.UserInfo(userinfo));
    }
    catch (RanteLoginException error)
    {
        return Pages.Error(error, logger);
    }
});

app.MapPost("/auth/sign-out", async (HttpContext context) =>
{
    var origin = context.Request.Headers.Origin.ToString();
    if (origin.Length > 0 && origin != siteOrigin)
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    // Signs out of this website only; the person stays signed in to Rante.
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    context.Session.Clear();
    return Results.Redirect("/");
});

app.Lifetime.ApplicationStarted.Register(() =>
    Console.WriteLine($"Sign in with Rante (ASP.NET Core example): {siteOrigin}/ - client {rante.ClientId}, {rante.ClientAuthentication}"));
app.Run();
return 0;

// A new sign-in for the person, in the authentication cookie; the access token (if any) goes in its properties.
static async Task StartSessionAsync(HttpContext context, ValidatedIdToken token, string? accessToken, string method)
{
    var claims = token.Identity.Claims
        .Select(claim => new Claim(claim.Type, claim.Value, claim.ValueType))
        .Append(new Claim(Pages.MethodClaim, method))
        .Append(new Claim(Pages.SignedInAtClaim, DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")));
    var properties = new AuthenticationProperties();
    if (accessToken is not null)
    {
        properties.StoreTokens([new AuthenticationToken { Name = "access_token", Value = accessToken }]);
    }

    context.Session.Clear(); // the used nonce and request go
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, "name", "roles")), properties);
}

sealed record FedCmSignIn(string? IdToken);

static class Keys
{
    public const string Nonce = "RanteLoginNonce";
    public const string Request = "RanteLoginRequest";
}

static class Pages
{
    public const string MethodClaim = "example_sign_in_method";
    public const string SignedInAtClaim = "example_signed_in_at";
    private const string SdkSrc = "https://login.rante.com/sdk/v1/rante-login.js";
    private const string SdkIntegrity = "sha384-2W12/NktCjRqFuXWiUtHr1yEtdrjBlCRWnJ+//FZMiqd1KRX/K+YMWLoMgF9R7wf";

    public static IResult Html(string html, int statusCode = StatusCodes.Status200OK) =>
        Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);

    public static string SignIn(RanteLoginClient rante, string nonce) => Layout("Sign in with Rante", $"""
            <h1>Sign in with Rante</h1>
            <p>ASP.NET Core example of the Rante Login SDK for .NET: the server finishes the sign-in and validates the ID token.</p>
            <div id="rante-signin"
                 data-client-id="{E(rante.ClientId)}"
                 data-redirect-uri="{E(rante.RedirectUri)}"
                 data-scope="{E(rante.Scope)}"
                 data-nonce="{E(nonce)}"></div>
            <p id="rante-signin-status" role="status"></p>
            <p><a href="/auth/rante/sign-in">Sign in without JavaScript</a> (the server starts the sign-in)</p>
            <script src="{SdkSrc}" integrity="{SdkIntegrity}" crossorigin="anonymous"></script>
            <script src="/signin.js"></script>
        """);

    public static string SignedIn(ClaimsPrincipal user)
    {
        var name = user.FindFirst("name")?.Value;
        var rows = Rows(user.Claims
            .Where(claim => claim.Type is not (MethodClaim or SignedInAtClaim))
            .GroupBy(claim => claim.Type)
            .Select(group => (group.Key, string.Join(", ", group.Select(claim => claim.Value)))));
        return Layout("Signed in", $"""
                <h1>Signed in{(name is null ? "" : $" as {E(name)}")}</h1>
                <p>This server validated the ID token below. Use <code>sub</code> as the person's ID on this website: it is
                   pairwise, so other organizations' apps see a different value.</p>
                <p>Signed in with: <strong>{E(user.FindFirst(MethodClaim)?.Value)}</strong>, {E(user.FindFirst(SignedInAtClaim)?.Value)}</p>
                <table><tbody>{rows}</tbody></table>
                <p><a href="/userinfo">Show userinfo</a></p>
                <form method="post" action="/auth/sign-out"><button type="submit">Sign out</button></form>
            """);
    }

    public static string UserInfo(Rante.Login.UserInfo userinfo) => Layout("Userinfo", $"""
            <h1>Userinfo</h1>
            <p>From GET https://login.rante.com/common/oidc/v2.0/userinfo:</p>
            <table><tbody>{Rows(userinfo.Claims.Select(claim => (claim.Key, claim.Value.ValueKind == JsonValueKind.String ? claim.Value.GetString() ?? "" : claim.Value.GetRawText())))}</tbody></table>
            <p><a href="/">Back</a></p>
        """);

    public static string Message(string title, string message) =>
        Layout(title, $"<h1>{E(title)}</h1><p>{E(message)}</p><p><a href=\"/\">Back</a></p>");

    public static IResult Error(RanteLoginException error, ILogger logger)
    {
        // Log the reason, never the code, the cookies or a token.
        logger.LogWarning("Sign-in failed: {Code}: {Message}", error.Code, error.Message);
        var message = error.Code == "access_denied" ? "The sign-in was cancelled on the Rante Login page." : error.Message;
        return Html(Layout("Sign-in failed", $"""
                <h1>Sign-in failed</h1>
                <p class="error"><code>{E(error.Code)}</code> {E(message)}</p>
                <p><a href="/">Try again</a></p>
            """), StatusCodes.Status400BadRequest);
    }

    private static string Rows(IEnumerable<(string Name, string Value)> rows) =>
        string.Concat(rows.Select(row => $"<tr><th><code>{E(row.Name)}</code></th><td>{E(row.Value)}</td></tr>"));

    private static string Layout(string title, string body) => $"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{E(title)} - ASP.NET Core example</title>
          <link rel="stylesheet" href="/style.css">
        </head>
        <body>
          <main>
        {body}
          </main>
        </body>
        </html>
        """;

    private static string E(string? value) => HtmlEncoder.Default.Encode(value ?? "");
}
