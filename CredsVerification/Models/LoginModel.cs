using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CredsVerification.Models;

/// <summary>
/// Standard request payload for login verification endpoints.
/// </summary>
public class LoginModel
{
    [Required]
    [JsonPropertyName("username")]
    public string username { get; set; } = string.Empty;

    [JsonPropertyName("accountNumber")]
    public string accountNumber { get; set; } = string.Empty;

    [JsonPropertyName("pin")]
    public string pin { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("password")]
    public string password { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("state")]
    public string state { get; set; } = string.Empty;
}
