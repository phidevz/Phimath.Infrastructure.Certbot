using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using ACMESharp.Authorizations;
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


var acmeClient = await AcmeClient.CreateAsync(certbotConfiguration.Acme, lf);


var apiClient = new ApiClient(certbotConfiguration.Credentials);

foreach (var (zoneName, zoneConfiguration) in certbotConfiguration.Zones)
{
    try
    {
        appLogger.LogInformation("Processing zone {0}", zoneName);
        if (!Utils.IsZoneValid(zoneName, zoneConfiguration.AdditionalSANs))
        {
            appLogger.LogCritical("All SANs must be subdomains of the defining zone {0}", zoneName);
            return 2;
        }

        appLogger.LogInformation("Getting zone information from Cloudflare");

        var zone = await apiClient.GetZone(zoneName);
        if (zone == null)
        {
            appLogger.LogError("Zone {0} not exist", zoneName);
            continue;
        }

        appLogger.LogInformation("Zone {0} has ID {1}", zoneName, zone.Id);
        appLogger.LogInformation("Now performing ACME actions");

        var order = await acmeClient.CreateOrderAsync(zoneName, zoneConfiguration.AdditionalSANs);
        if (order.Payload.Status == AcmeClient.Status.Pending)
        {
            appLogger.LogInformation("Processing authorizations of order {0} for zone {1}", order.OrderUrl, zoneName);

            foreach (var authorizationUrl in order.Payload.Authorizations)
            {
                var authorization = await acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                appLogger.LogInformation(
                    "Processing authorization for {0} with {1} challenge(s), initial status {2}",
                    authorization.Identifier,
                    authorization.Challenges.Length,
                    authorization.Status);

                foreach (var challenge in authorization.Challenges)
                {
                    if (challenge.Type != Dns01ChallengeValidationDetails.Dns01ChallengeType)
                    {
                        appLogger.LogDebug("Skipping non-DNS challenge of type {0}", challenge.Type);
                        continue;
                    }

                    var dnsChallenge = AuthorizationDecoder.ResolveChallengeForDns01(
                        authorization,
                        challenge,
                        acmeClient.Signer);

                    appLogger.LogInformation(
                        "DNS challenge is: [{0}] {1}={2}",
                        dnsChallenge.DnsRecordName,
                        dnsChallenge.DnsRecordType,
                        dnsChallenge.DnsRecordValue);

                    if (challenge.Status != AcmeClient.Status.Pending)
                    {
                        appLogger.LogWarning(
                            "Challenge is {0}, but expected status was {1}",
                            challenge.Status,
                            AcmeClient.Status.Pending);
                    }
                    else
                    {
                        if (!Enum.TryParse(dnsChallenge.DnsRecordType, true, out DnsRecordTypes challengeRecordType))
                        {
                            appLogger.LogWarning(
                                "Challenge requested unsupported DNS record type {0}, falling back to TXT",
                                dnsChallenge.DnsRecordType);
                            challengeRecordType = DnsRecordTypes.TXT;
                        }

                        appLogger.LogInformation("Checking for existing challenges in zone {0}", zoneName);

                        var existingRecords = await apiClient.GetDnsRecords(
                            zone,
                            dnsChallenge.DnsRecordName,
                            challengeRecordType);

                        appLogger.LogInformation(
                            "Found {0} existing record(s) for that challenge type and name",
                            existingRecords.Count);
                    }
                }
            }
        }

        var _ = 0;
    }
    catch (Exception ex)
    {
        appLogger.LogError(ex, "Error processing zone {0}", zoneName);
    }
}

return 0;