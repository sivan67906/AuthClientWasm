using AuthClient.Shared.DTOs;

namespace AuthClient.BlazorWasm.Services;

public interface IAuthenticationService
{
    Task<ApiResponse<LoginResponse>> LoginAsync(LoginRequest request);
    Task<ApiResponse<RegisterResponse>> RegisterAsync(RegisterRequest request);
    Task LogoutAsync();
    Task<bool> RefreshTokenAsync();
    Task<ApiResponse> ChangePasswordAsync(string currentPassword, string newPassword);
    Task<ApiResponse> ForgotPasswordAsync(string email);
    Task<ApiResponse> ResetPasswordAsync(string email, string token, string newPassword);
}