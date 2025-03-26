using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
//using System.Timers;

namespace BlazorOidc;

public sealed class OidcCookieRefresher
{
    private readonly ILogger<OidcCookieRefresher> _logger;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptionsMonitor;
    private readonly SemaphoreSlim _lock = new(1, 1);
    //private readonly System.Timers.Timer _timer = new(TimeSpan.FromMinutes(1)) { AutoReset = true };

    //private CookieValidatePrincipalContext? _lastUsedValidationContext;  

    public OidcCookieRefresher(IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor, ILogger<OidcCookieRefresher> logger)
    {
        _oidcOptionsMonitor = oidcOptionsMonitor;
        _logger = logger;
        //_timer.Elapsed += async (sender, args) => await TimerElapsed(sender, args);
    }

    //private async Task TimerElapsed(object? sender, ElapsedEventArgs e)
    //{
    //    _logger.LogInformation("Timer to validate or refresh cookie elapsed.");

    //    if (_lastUsedValidationContext is null)
    //    {
    //        return;
    //    }

    //    await ValidateOrRefreshCookieAsync(_lastUsedValidationContext);
    //}

    private readonly OpenIdConnectProtocolValidator oidcTokenValidator = new()
    {
        // We no longer have the original nonce cookie which is deleted at the end of the authorization code flow having served its purpose.
        // Even if we had the nonce, it's likely expired. It's not intended for refresh requests. Otherwise, we'd use oidcOptions.ProtocolValidator.
        RequireNonce = false,
    };

    public async Task ValidateOrRefreshCookieAsync(CookieValidatePrincipalContext validateContext)
    {
        try
        {
            if (await _lock.WaitAsync(TimeSpan.FromSeconds(5)))
            {
                //if (_lastUsedValidationContext is null)
                //{
                //    _timer.Start();
                //}

                //_lastUsedValidationContext = validateContext;

                _logger.LogInformation("Validating cookie...");

                var accessTokenExpirationText = validateContext.Properties.GetTokenValue("expires_at");

                if (!DateTimeOffset.TryParse(accessTokenExpirationText, out var accessTokenExpiration))
                {
                    return;
                }

                var oidcOptions = _oidcOptionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
                var now = oidcOptions.TimeProvider!.GetUtcNow();

                if (now + TimeSpan.FromMinutes(5) < accessTokenExpiration)
                {
                    _logger.LogInformation("Cookie is still valid.");
                    return;
                }

                _logger.LogInformation("Cookie expired, refreshing now.");

                var oidcConfiguration = await oidcOptions.ConfigurationManager!.GetConfigurationAsync(validateContext.HttpContext.RequestAborted);
                var tokenEndpoint = oidcConfiguration.TokenEndpoint ?? throw new InvalidOperationException("Cannot refresh cookie. TokenEndpoint is missing!");

                using var refreshResponse = await oidcOptions.Backchannel.PostAsync(tokenEndpoint,
                    new FormUrlEncodedContent(new Dictionary<string, string>()
                    {
                        ["grant_type"] = "refresh_token",
                        ["client_id"] = oidcOptions.ClientId,
                        ["client_secret"] = oidcOptions.ClientSecret,
                        ["scope"] = string.Join(" ", oidcOptions.Scope),
                        ["refresh_token"] = validateContext.Properties.GetTokenValue("refresh_token")
                    }));

                if (!refreshResponse.IsSuccessStatusCode)
                {
                    validateContext.RejectPrincipal();
                    return;
                }

                var refreshJson = await refreshResponse.Content.ReadAsStringAsync();
                var message = new OpenIdConnectMessage(refreshJson);
                var validationParameters = oidcOptions.TokenValidationParameters.Clone();

                if (oidcOptions.ConfigurationManager is BaseConfigurationManager baseConfigurationManager)
                {
                    validationParameters.ConfigurationManager = baseConfigurationManager;
                }
                else
                {
                    validationParameters.ValidIssuer = oidcConfiguration.Issuer;
                    validationParameters.IssuerSigningKeys = oidcConfiguration.SigningKeys;
                }

                var validationResult = await oidcOptions.TokenHandler.ValidateTokenAsync(message.IdToken, validationParameters);

                if (!validationResult.IsValid)
                {
                    validateContext.RejectPrincipal();
                    return;
                }

                var validatedIdToken = JwtSecurityTokenConverter.Convert(validationResult.SecurityToken as JsonWebToken);
                validatedIdToken.Payload["nonce"] = null;

                oidcTokenValidator.ValidateTokenResponse(new()
                {
                    ProtocolMessage = message,
                    ClientId = oidcOptions.ClientId,
                    ValidatedIdToken = validatedIdToken
                });

                validateContext.ShouldRenew = true;
                validateContext.ReplacePrincipal(new ClaimsPrincipal(validationResult.ClaimsIdentity));

                var expiresIn = int.Parse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture);
                var expiresAt = now + TimeSpan.FromSeconds(expiresIn);
                validateContext.Properties.StoreTokens([
                    new() { Name = "access_token", Value = message.AccessToken },
                    new() { Name = "id_token", Value = message.IdToken },
                    new() { Name = "refresh_token", Value = message.RefreshToken },
                    new() { Name = "token_type", Value = message.TokenType },
                    new() { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) },
                ]);

                _logger.LogInformation("Cookie refreshed.");
            }
        }
        finally
        {
            _lock.Release();
        }
    }
}