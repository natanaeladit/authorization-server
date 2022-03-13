using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using server.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<AuthorizationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<AuthorizationDbContext>();
    })
    .AddServer(options =>
    {
        options.SetTokenEndpointUris("/connect/token")
               .SetAuthorizationEndpointUris("/connect/authorize")
               //.SetLogoutEndpointUris("/connect/logout")
               .SetUserinfoEndpointUris("/connect/userinfo");

        options.AllowClientCredentialsFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow();

        options.RegisterScopes(
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Email,
                OpenIddictConstants.Scopes.Roles
                );

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               //.EnableLogoutEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough()
               .EnableStatusCodePagesIntegration();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictConstants.Schemes.Bearer;
    options.DefaultChallengeScheme = OpenIddictConstants.Schemes.Bearer;
});

builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<AuthorizationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
    options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
    options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
    options.SignIn.RequireConfirmedAccount = false;
});

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
app.MapGet("/", () => "Authorization Server is running");
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapDefaultControllerRoute();
});
if (args.Length > 0 && args[0] == "-u")
{
    Console.WriteLine("updating database ...");
    var serviceProvider = builder.Services.BuildServiceProvider();
    await using var scope = serviceProvider.CreateAsyncScope();
    var context = scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>();
    await context.Database.MigrateAsync();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    if (await manager.FindByClientIdAsync("console") == null)
    {
        Console.WriteLine("adding console client ...");
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "console",
            ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
            DisplayName = "My client application",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.ClientCredentials,
            }
        });
    }
    if (await manager.FindByClientIdAsync("web") == null)
    {
        Console.WriteLine("adding web client ...");
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "web",
            ClientSecret = "BEB06826-0308-4DFD-AEDD-3D04F6808901",
            DisplayName = "My web application",
            Permissions =
            {
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.Password,
            }
        });
    }
    Console.WriteLine("database was updated successfully...");
    Environment.Exit(0);
}
app.Run();
