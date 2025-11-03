namespace AuthClient.Shared.DTOs;

public record LoginRequest(string Email, string Password, string ClientId);

public record RegisterRequest(
    string Email, 
    string Password, 
    string ConfirmPassword, 
    string? FullName);

public record LoginResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpires,
    DateTime RefreshTokenExpires,
    UserInfo User);

public record RegisterResponse(
    Guid Id,
    string Email,
    string? FullName,
    DateTime CreatedAt);

public record UserInfo(
    Guid Id,
    string Email,
    string? FullName,
    IList<string> Roles);

public record ApiResponse<T>
{
    public bool Success { get; init; }
    public T? Data { get; init; }
    public string? Message { get; init; }
    public List<string>? Errors { get; init; }
    public DateTime Timestamp { get; init; }
}

public record ApiResponse
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    public List<string>? Errors { get; init; }
    public DateTime Timestamp { get; init; }
}
