
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

try
{
    var configuration = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json", optional: false)
        .Build();

    var useAzureDefaultCredentials = bool.Parse(configuration["UseAzureDefaultCredentials"]!);
    var includeInteractiveCredentials = bool.Parse(configuration["IncludeInteractiveCredentials"]!);
    var clientId = configuration["ClientId"];
    var tenantId = configuration["TenantId"];
    var azureIdentityResourceUri = configuration["AzureIdentityResourceUri"];
    var azureIdentityScopeCollection = configuration.GetSection("AzureIdentityScopeCollection").Get<string[]>()!;
    var parentRequestId = configuration["ParentRequestId"];
    var claims = configuration["Claims"];
    var isCaeEnabled = bool.Parse(configuration["IsCaeEnabled"]!);

    Console.WriteLine($"{nameof(useAzureDefaultCredentials)}: {useAzureDefaultCredentials}");
    Console.WriteLine($"{nameof(includeInteractiveCredentials)}: {includeInteractiveCredentials}");
    Console.WriteLine($"{nameof(clientId)}: {clientId}");
    Console.WriteLine($"{nameof(tenantId)}: {tenantId}");
    Console.WriteLine($"{nameof(azureIdentityResourceUri)}: {azureIdentityResourceUri}");
    Console.WriteLine($"{nameof(azureIdentityScopeCollection)}: {string.Join(';', azureIdentityScopeCollection)}");
    Console.WriteLine($"{nameof(parentRequestId)}: {parentRequestId}");
    Console.WriteLine($"{nameof(claims)}: {claims}");
    Console.WriteLine($"{nameof(isCaeEnabled)}: {isCaeEnabled}");

    Console.WriteLine($"{DateTime.Now} | Creating TokenRequestContext");

    var tokenRequestContext = new TokenRequestContext(
        scopes: azureIdentityScopeCollection,
        parentRequestId,
        claims,
        tenantId,
        isCaeEnabled
    );

    if (useAzureDefaultCredentials)
    {
        Console.WriteLine($"{DateTime.Now} | Creating DefaultAzureCredential");
        var azureCredential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeInteractiveBrowserCredential = !includeInteractiveCredentials,
            ExcludeAzureDeveloperCliCredential = true,
            ExcludeAzurePowerShellCredential = true,
            ExcludeVisualStudioCodeCredential = true,
            ExcludeVisualStudioCredential = true
        });

        Console.WriteLine($"{DateTime.Now} | GetTokenAsync");
        var token = await azureCredential.GetTokenAsync(tokenRequestContext);

        Console.WriteLine($"{DateTime.Now} | Token: {token.Token}");
    }
    else
    {
        var scopes = new[] { "User.Read" };

        var options = new BrokerOptions(BrokerOptions.OperatingSystems.Windows)
        {
            Title = "XOne - Token Demo"
        };

        var app =
            PublicClientApplicationBuilder.Create(clientId)
            .WithDefaultRedirectUri()
            .WithTenantId(tenantId)
            .WithBroker(options)
            .Build();

        AuthenticationResult result = null;

        try
        {
            Console.WriteLine($"{DateTime.Now} | AcquireTokenByIntegratedWindowsAuth");
            result = await app.AcquireTokenByIntegratedWindowsAuth(scopes)
                .ExecuteAsync();
        }
        // Can't get a token silently, go interactive
        catch (MsalUiRequiredException ex)
        {
            Console.WriteLine($"{DateTime.Now} | ExceptionType: {ex} | Exception.Message: {ex.Message} | Exception.InnerException.Message: {ex.InnerException?.Message}");

            result = await app.AcquireTokenInteractive(scopes).ExecuteAsync();
        }

        Console.WriteLine($"{DateTime.Now} | AccessToken: {result.AccessToken}");
    }
}
catch (Exception ex)
{
    Console.WriteLine($"{DateTime.Now} | ExceptionType: {ex} | Exception.Message: {ex.Message} | Exception.InnerException.Message: {ex.InnerException?.Message}");
}

Console.WriteLine();
Console.WriteLine("Press [ENTER] to close...");
Console.ReadLine();

