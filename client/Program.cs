using IdentityModel.Client;
using System.Diagnostics;

try
{
    Console.WriteLine($"Retrieving token ...");
    Stopwatch sw = new Stopwatch();
    sw.Start();
    using HttpClient client = new HttpClient();
    string token = await GetTokenAsync(client);
    sw.Stop();
    Console.WriteLine($"Token: {token} elapsed: {sw.ElapsedMilliseconds}ms");
}
catch (Exception ex)
{
    Console.WriteLine(ex.Message);
    Console.WriteLine(ex.InnerException?.Message);
}
Console.Read();

static async Task<string> GetTokenAsync(HttpClient client)
{
    var configuration = await client.GetDiscoveryDocumentAsync("https://localhost:5001");
    if (configuration.IsError)
    {
        throw new Exception($"An error occurred while retrieving the configuration document: {configuration.Error}");
    }

    var response = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
    {
        Address = configuration.TokenEndpoint,
        ClientId = "console",
        ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207"
    });

    if (response.IsError)
    {
        throw new Exception($"An error occurred while retrieving an access token: {response.Error}");
    }

    return response.AccessToken;
}