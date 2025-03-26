namespace BlazorOidc;

using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Net.Http.Headers;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly HttpClient _httpClient;

    public CustomAuthStateProvider(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await GetTokenFromCookie();

        var identity = new ClaimsIdentity();
        if (!string.IsNullOrEmpty(token))
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            identity = new ClaimsIdentity(jwtToken.Claims, "jwt");

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var user = new ClaimsPrincipal(identity);
        return new AuthenticationState(user);
    }

    private async Task<string> GetTokenFromCookie()
    {
        var response = await _httpClient.GetAsync("https://localhost:7098/api/account/token");
        if (response.IsSuccessStatusCode)
        {
            return await response.Content.ReadAsStringAsync();
        }
        return string.Empty;
    }
}
