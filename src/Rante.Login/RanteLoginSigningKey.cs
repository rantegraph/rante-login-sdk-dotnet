using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

namespace Rante.Login;

/// <summary>
/// A Signed JWT key linked to the app: its prefix as the Rante Portal shows it (sent as the client assertion's
/// <c>kid</c>) and its private key, RSA of at least 2048 bits (RS256) or EC P-256 (ES256).
/// </summary>
public sealed class RanteLoginSigningKey
{
    private static readonly Regex KeyPrefixPattern = new("^rk_live_[0-9a-f]{24}$", RegexOptions.CultureInvariant);

    private RanteLoginSigningKey(string keyPrefix, SigningCredentials credentials)
    {
        KeyPrefix = keyPrefix;
        Credentials = credentials;
    }

    /// <summary>The key's prefix (rk_live_ and 24 hex digits).</summary>
    public string KeyPrefix { get; }

    /// <summary><c>RS256</c> or <c>ES256</c>.</summary>
    public string Algorithm => Credentials.Algorithm;

    internal SigningCredentials Credentials { get; }

    /// <summary>From an unencrypted PEM private key (PKCS#8, or the RSA and EC forms).</summary>
    public static RanteLoginSigningKey FromPem(string keyPrefix, string privateKeyPem)
    {
        CheckPrefix(keyPrefix);
        if (string.IsNullOrEmpty(privateKeyPem) || !privateKeyPem.Contains("PRIVATE KEY-----", StringComparison.Ordinal)
            || privateKeyPem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
        {
            throw Invalid("The signing key must be an unencrypted PEM private key (-----BEGIN PRIVATE KEY-----).");
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(privateKeyPem);
            return FromRsa(keyPrefix, rsa);
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(privateKeyPem);
        }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        {
            ecdsa.Dispose();
            throw Invalid("The signing key could not be read: it must be an RSA or EC P-256 private key.");
        }

        return FromECDsa(keyPrefix, ecdsa);
    }

    /// <summary>From an RSA private key of at least 2048 bits (RS256). The key must stay alive with the client.</summary>
    public static RanteLoginSigningKey FromRsa(string keyPrefix, RSA privateKey)
    {
        CheckPrefix(keyPrefix);
        if (privateKey.KeySize < 2048)
        {
            throw Invalid("RSA signing keys must have at least 2048 bits.");
        }

        return new RanteLoginSigningKey(keyPrefix,
            new SigningCredentials(new RsaSecurityKey(privateKey) { KeyId = keyPrefix }, SecurityAlgorithms.RsaSha256));
    }

    /// <summary>From an EC P-256 private key (ES256). The key must stay alive with the client.</summary>
    public static RanteLoginSigningKey FromECDsa(string keyPrefix, ECDsa privateKey)
    {
        CheckPrefix(keyPrefix);
        if (privateKey.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
        {
            throw Invalid("EC signing keys must use the P-256 curve (ES256).");
        }

        return new RanteLoginSigningKey(keyPrefix,
            new SigningCredentials(new ECDsaSecurityKey(privateKey) { KeyId = keyPrefix }, SecurityAlgorithms.EcdsaSha256));
    }

    private static void CheckPrefix(string keyPrefix)
    {
        if (string.IsNullOrEmpty(keyPrefix) || !KeyPrefixPattern.IsMatch(keyPrefix))
        {
            throw Invalid("The key prefix must be the one the Rante Portal shows: rk_live_ and 24 hex digits.");
        }
    }

    private static RanteLoginException Invalid(string message) => new("invalid_configuration", message);
}
