using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Blazored.LocalStorage;

namespace AuthClient.BlazorWasm.Services;

public sealed class TokenService : ITokenService
{
    private readonly ILocalStorageService _localStorage;
    private readonly ILogger<TokenService> _logger;
    private const string AccessTokenKey = "accessToken";
    private const string RefreshTokenKey = "refreshToken";

    public TokenService(
        ILocalStorageService localStorage,
        ILogger<TokenService> logger)
    {
        _localStorage = localStorage;
        _logger = logger;
    }

    public async Task<string?> GetAccessTokenAsync()
    {
        try
        {
            return await _localStorage.GetItemAsync<string>(AccessTokenKey);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving access token from local storage");
            return null;
        }
    }

    public async Task<string?> GetRefreshTokenAsync()
    {
        try
        {
            return await _localStorage.GetItemAsync<string>(RefreshTokenKey);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving refresh token from local storage");
            return null;
        }
    }

    public async Task SetTokensAsync(string accessToken, string refreshToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);

        try
        {
            await _localStorage.SetItemAsync(AccessTokenKey, accessToken);
            await _localStorage.SetItemAsync(RefreshTokenKey, refreshToken);
            _logger.LogInformation("Authentication tokens stored successfully in local storage");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error storing authentication tokens in local storage");
            throw;
        }
    }

    public async Task ClearTokensAsync()
    {
        try
        {
            await _localStorage.RemoveItemAsync(AccessTokenKey);
            await _localStorage.RemoveItemAsync(RefreshTokenKey);
            _logger.LogInformation("Authentication tokens cleared from local storage");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error clearing authentication tokens from local storage");
        }
    }

    public async Task<bool> IsTokenValidAsync()
    {
        var token = await GetAccessTokenAsync();
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger.LogDebug("No access token found for validation");
            return false;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var isValid = jwtToken.ValidTo > DateTime.UtcNow;

            _logger.LogDebug("Token validation result: {IsValid}, Expires: {ExpirationTime}",
                isValid, jwtToken.ValidTo);

            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating JWT token");
            return false;
        }
    }

    public async Task<ClaimsPrincipal?> GetUserFromTokenAsync()
    {
        var token = await GetAccessTokenAsync();
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger.LogDebug("No access token found for parsing user claims");
            return null;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var identity = new ClaimsIdentity(jwtToken.Claims, "jwt");
            return new ClaimsPrincipal(identity);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing user claims from JWT token");
            return null;
        }
    }

    public async Task<DateTime?> GetTokenExpirationAsync()
    {
        var token = await GetAccessTokenAsync();
        if (string.IsNullOrWhiteSpace(token))
            return null;

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken.ValidTo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting token expiration time");
            return null;
        }
    }
}