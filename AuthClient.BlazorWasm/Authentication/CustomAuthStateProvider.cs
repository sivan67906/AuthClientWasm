using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthClient.BlazorWasm.Services;
using Microsoft.AspNetCore.Components.Authorization;

namespace AuthClient.BlazorWasm.Authentication;

public sealed class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly ITokenService _tokenService;
    private readonly ILogger<CustomAuthStateProvider> _logger;
    private readonly AuthenticationState _anonymous;
    private bool _isInitialized;

    public CustomAuthStateProvider(
        ITokenService tokenService,
        ILogger<CustomAuthStateProvider> logger)
    {
        _tokenService = tokenService;
        _logger = logger;
        _anonymous = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!_isInitialized)
        {
            _isInitialized = true;
            _logger.LogInformation("Authentication state provider initialized");
        }

        try
        {
            var token = await _tokenService.GetAccessTokenAsync();

            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogDebug("No access token found, returning anonymous state");
                return _anonymous;
            }

            var claims = ParseClaimsFromJwt(token);
            var expiryClaim = claims.FirstOrDefault(c => c.Type == "exp")?.Value;

            if (expiryClaim is not null && long.TryParse(expiryClaim, out var exp))
            {
                var expiryDate = DateTimeOffset.FromUnixTimeSeconds(exp);
                if (expiryDate < DateTimeOffset.UtcNow)
                {
                    _logger.LogWarning("Access token has expired, clearing authentication");
                    await ClearAuthenticationAsync();
                    return _anonymous;
                }
            }

            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            var userName = user.Identity?.Name ?? "Unknown";
            _logger.LogDebug("User authenticated: {UserName}", userName);

            return new AuthenticationState(user);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving authentication state");
            return _anonymous;
        }
    }

    public async Task NotifyUserAuthentication(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        try
        {
            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "jwt");
            var user = new ClaimsPrincipal(identity);

            var authState = Task.FromResult(new AuthenticationState(user));
            NotifyAuthenticationStateChanged(authState);

            var userName = user.Identity?.Name ?? "Unknown";
            _logger.LogInformation("User authenticated and state updated: {UserName}", userName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error notifying user authentication");
        }
    }

    public async Task NotifyUserLogout()
    {
        try
        {
            await ClearAuthenticationAsync();
            var authState = Task.FromResult(_anonymous);
            NotifyAuthenticationStateChanged(authState);

            _logger.LogInformation("User logged out and authentication state cleared");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error notifying user logout");
        }
    }

    private async Task ClearAuthenticationAsync()
    {
        try
        {
            await _tokenService.ClearTokensAsync();
            _logger.LogDebug("Authentication tokens cleared");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error clearing authentication");
        }
    }

    private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);
            return token.Claims;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing JWT claims");
            return Enumerable.Empty<Claim>();
        }
    }
}