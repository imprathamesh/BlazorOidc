using BlazorOidc;
using BlazorOidc.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddSingleton<WeatherForecastService>();

builder.Services.AddAuthorizationCore(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

//builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"C:\keys"))
    .SetApplicationName("BlazorOidc");

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax; // Change to Lax instead of None
    options.Cookie.HttpOnly = true;
    options.Cookie.Name = ".BlazorOidc.Auth";
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = "https://localhost:7098/";
    options.ClientId = "clientone";
    options.ClientSecret = "your-secret";
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.ResponseMode = OpenIdConnectResponseMode.Query;
    options.SaveTokens = true;
    //options.GetClaimsFromUserInfoEndpoint = true;
    //options.MetadataAddress = "https://localhost:7098/.well-known/openid-configuration";
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        //IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("907A6D3546002CE8744DC03DC455A556")),
        ClockSkew = TimeSpan.Zero,
        RoleClaimType = "groups",
        NameClaimType = "name",
        ValidIssuer = "https://localhost:7098/",
        ValidAudience = "api1"
    };
    options.Scope.Add(OpenIdConnectScope.Email);
    options.Scope.Add(OpenIdConnectScope.OpenIdProfile);
    options.Scope.Add("api1");
    options.MapInboundClaims = false;
    options.UsePkce = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.SaveTokens = true;
    options.SignedOutCallbackPath = new PathString("/authentication/logout-callback");
    options.CallbackPath = new PathString("/authentication/login-callback");
    //options.SignedOutCallbackPath = new PathString("/authentication/login-callback");
    //options.RemoteSignOutPath = new PathString("/signout-oidc");
});

builder.Services.AddSingleton<OidcCookieRefresher>();
builder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .Configure<OidcCookieRefresher>((options, refresher) =>
    {
        options.Events.OnValidatePrincipal = context => refresher.ValidateOrRefreshCookieAsync(context);
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

//ORDER IS IMPORTANT: routing => authentication => authorization => antiforgery => endpoints
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

//ENDPOINTS
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapBlazorHub(options =>
{
    options.CloseOnAuthenticationExpiration = true;
}).WithOrder(-1);

app.MapRazorPages();

app.MapGroup("/authentication")
    .MapLoginAndLogout();

app.Run();
