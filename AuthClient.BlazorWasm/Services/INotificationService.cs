namespace AuthClient.BlazorWasm.Services;

public interface INotificationService
{
    Task ShowSuccessAsync(string message, int durationMs = 3000);
    Task ShowErrorAsync(string message, int durationMs = 5000);
    Task ShowInfoAsync(string message, int durationMs = 3000);
    Task ShowWarningAsync(string message, int durationMs = 4000);

    event Action<NotificationMessage>? OnNotification;
}

public sealed record NotificationMessage(
    string Message,
    NotificationType Type,
    int DurationMs);

public enum NotificationType
{
    Success,
    Error,
    Info,
    Warning
}