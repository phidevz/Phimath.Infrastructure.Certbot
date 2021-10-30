using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Serialization;
using OLT.CloudFlare;
using Phimath.Infrastructure.Certbot;
using Phimath.Infrastructure.Certbot.Acme;
using Phimath.Infrastructure.Certbot.Cloudflare;
using Phimath.Infrastructure.Certbot.Configuration;

var lf = LoggerFactory.Create(logging => logging.AddConsole().AddFilter(level => level != LogLevel.Trace));
var appLogger = lf.CreateLogger("AppLogger");

IConfiguration configuration;
try
{
    configuration = new ConfigurationBuilder()
        .AddCommandLine(args)
        .SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location))
        .AddJsonFile("certbot.json", reloadOnChange: true, optional: false)
        .Build();
}
catch (Exception ex)
{
    appLogger.LogCritical(ex, "Cannot load configuration");
    return 1;
}

var certbotConfiguration = configuration.GetSection("Certbot").Get<CertbotConfiguration>();

var acmeClient = AcmeClient.CreateAsync(certbotConfiguration.Acme, lf);
var apiClient = new ApiClient(certbotConfiguration.Credentials);

foreach (var (zoneName, zoneConfiguration) in certbotConfiguration.Zones)
{
    appLogger.LogInformation("Processing zone {0}", zoneName);

    zoneConfiguration.AdditionalSANs ??= new List<string>();

    foreach (var additionalSAN in zoneConfiguration.AdditionalSANs)
    {
        if (!additionalSAN.EndsWith(zoneName))
        {
            appLogger.LogError("Error: SAN {0} must be a subdomain of the zone {1}", additionalSAN, zoneName);
            return 2;
        }
    }

    appLogger.LogInformation("Getting zone information from Cloudflare");

    var zone = await apiClient.GetZone(zoneName);
    if (zone == null)
    {
        appLogger.LogError("Zone {0} not exist", zoneName);
        continue;
    }

    appLogger.LogInformation("Zone {0} has ID {1}", zoneName, zone.Id);
    appLogger.LogInformation("Checking for existing challenges in zone {0}", zoneName);
    
    var existingRecords = await apiClient.GetDnsRecords(zone, dnsRecordTypes: DnsRecordTypes.TXT).AndThen(records => records.Where(record => record.Name.StartsWith("_acme-challenge")).ToList());
    var _ = 0;
}

return 0;