using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Phimath.Infrastructure.Certbot;
using Phimath.Infrastructure.Certbot.Configuration;
using TaskExtensions = LanguageExt.TaskExtensions;

var lf = LoggerFactory.Create(logging => logging.AddConsole().AddFilter(level => level != LogLevel.Trace));
var appLogger = lf.CreateLogger("AppLogger");

IConfiguration configuration;
try
{
    IDictionary<string, string> switchMappings = new Dictionary<string, string>
    {
        { "-staging", "Certbot:Acme:UseStaging" },
        { "-state", "Certbot:Acme:StateDirectory" },
        { "--link-into", "Certbot:Acme:LinkInto" }
    };

    configuration = new ConfigurationBuilder()
        .SetBasePath(Environment.CurrentDirectory)
        .AddJsonFile("certbot.json", reloadOnChange: true, optional: false)
        .AddCommandLine(args, switchMappings)
        .Build();
}
catch (Exception ex)
{
    appLogger.LogCritical(ex, "Cannot load configuration");
    return 1;
}

var certbotConfiguration = configuration.GetSection("Certbot").Get<CertbotConfiguration>();

await Workflow
    .Configure(certbotConfiguration, lf)
    .ValidateConfiguration()
    .CollectErrors()
    .InitClients()
    .ProcessZones();

return 0;