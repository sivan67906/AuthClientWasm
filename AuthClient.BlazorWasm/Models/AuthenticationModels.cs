namespace AuthClient.BlazorWasm.Models;

// Request DTOs
public sealed record LoginRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public bool RememberMe { get; init; }
}

public sealed record RegisterRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string ConfirmPassword { get; init; }
    public string? FullName { get; init; }
}

public sealed record ChangePasswordRequest
{
    public required string CurrentPassword { get; init; }
    public required string NewPassword { get; init; }
}

public sealed record ForgotPasswordRequest
{
    public required string Email { get; init; }
}

public sealed record ResetPasswordRequest
{
    public required string Email { get; init; }
    public required string Token { get; init; }
    public required string NewPassword { get; init; }
}

public sealed record UpdateProfileRequest
{
    public string? FullName { get; init; }
    public string? Email { get; init; }
}

public sealed record RefreshTokenRequest
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
}

// Response DTOs
public sealed record ApiResponse
{
    public required bool Success { get; init; }
    public string? Message { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

public sealed record AuthResponse : ApiResponse
{
    public required string AccessToken { get; init; }
    public required string RefreshToken { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public required UserInfo User { get; init; }
}

public sealed record UserInfo
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public string? FullName { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
}

public sealed record UserProfile
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public string? FullName { get; init; }
    public required IReadOnlyList<string> Roles { get; init; }
    public required DateTime CreatedAt { get; init; }
    public DateTime? LastLoginAt { get; init; }
    public bool EmailConfirmed { get; init; }
    public bool TwoFactorEnabled { get; init; }
}

public sealed record ValidationError
{
    public required string Field { get; init; }
    public required string Message { get; init; }
}

public sealed record ValidationResponse : ApiResponse
{
    public required IReadOnlyList<ValidationError> Errors { get; init; }
}
