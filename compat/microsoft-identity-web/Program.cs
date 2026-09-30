// Minimal Entra-style web API: Microsoft.Identity.Web validates bearer tokens
// issued by rust-oidc. Configuration is the standard "AzureAd" section, supplied
// by compat/run.sh through AzureAd__* environment variables.
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

// Expose claims under their on-the-wire names (scp, tid, roles) instead of the
// legacy WS-* URIs. This only changes claim naming, not validation.
builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme,
    options => options.MapInboundClaims = false);

builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => "ok");
app.MapGet("/whoami", (ClaimsPrincipal user) =>
{
    // Raw claim types as in the token (MapInboundClaims is off in Microsoft.Identity.Web).
    var claims = user.Claims.GroupBy(c => c.Type).ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());
    return Results.Json(claims);
}).RequireAuthorization();

app.Run();
