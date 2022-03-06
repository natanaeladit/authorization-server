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
builder.Services.AddOpenIddict().AddCore(options =>
{
    options.UseEntityFrameworkCore().UseDbContext<AuthorizationDbContext>();
}).AddServer(options =>
{
    options.SetTokenEndpointUris("/connect/token");
    options.AllowClientCredentialsFlow();
    options.AddDevelopmentEncryptionCertificate()
           .AddDevelopmentSigningCertificate();
    options.UseAspNetCore()
           .EnableTokenEndpointPassthrough();
}).AddValidation(options =>
{
    options.UseLocalServer();
    options.UseAspNetCore();
}); ;

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
if (args.Length > 0 && args[0] == "-update")
{
    Console.WriteLine("updating database ...");
    var serviceProvider = builder.Services.BuildServiceProvider();
    await using var scope = serviceProvider.CreateAsyncScope();
    var context = scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>();
    await context.Database.EnsureCreatedAsync();
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
                Permissions.GrantTypes.ClientCredentials
            }
        });
    }
    Console.WriteLine("database was updated successfully...");
    Environment.Exit(0);
}
app.Run();
