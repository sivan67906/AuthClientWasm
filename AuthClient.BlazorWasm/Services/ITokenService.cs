using System.Security.Claims;

namespace AuthClient.BlazorWasm.Services;

public interface ITokenService
{
    Task<string?> GetAccessTokenAsync();
    Task<string?> GetRefreshTokenAsync();
    Task SetTokensAsync(string accessToken, string refreshToken);
    Task ClearTokensAsync();
    Task<bool> IsTokenValidAsync();
    Task<ClaimsPrincipal?> GetUserFromTokenAsync();
    Task<DateTime?> GetTokenExpirationAsync();
}