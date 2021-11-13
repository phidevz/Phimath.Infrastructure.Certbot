using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Serialization;
using OLT.CloudFlare;
using Phimath.Infrastructure.Certbot;
using Phimath.Infrastructure.Certbot.Acme;
using Phimath.Infrastructure.Certbot.Cloudflare;
using Phimath.Infrastructure.Certbot.Cloudflare.Dtos;
using Phimath.Infrastructure.Certbot.Configuration;
using PKISharp.SimplePKI;

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
KeyAlgorithm keyAlgorithm;
switch (certbotConfiguration.Acme.KeyAlgorithm)
{
    case KeyAlgorithm.Invalid:
        appLogger.LogCritical("KeyAlgorithm is invalid, can only be ECDSA or RSA");
        return 5;
    case null:
        keyAlgorithm = KeyAlgorithm.ECDSA;
        break;
    default:
        keyAlgorithm = certbotConfiguration.Acme.KeyAlgorithm.Value;
        break;
}

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

        var normalizedSANs = zoneConfiguration.AdditionalSANs.Prepend(zoneName).Distinct().ToImmutableList();

        var order = await acmeClient.CreateOrderAsync(zoneName, normalizedSANs);
        if (order.Payload.Status == AcmeClient.Status.Pending)
        {
            appLogger.LogInformation("Processing authorizations of order {0} for zone {1}", order.OrderUrl, zoneName);

            var authorizationResults = new List<Authorization>(order.Payload.Authorizations.Length);
            var dnsRecordsInCurrentOrder = new HashSet<string>();

            foreach (var authorizationUrl in order.Payload.Authorizations)
            {
                var authorization = await acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                appLogger.LogInformation(
                    "Processing authorization for {0}:{1} with {2} challenge(s), initial status {3}",
                    authorization.Identifier.Type,
                    authorization.Identifier.Value,
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

                        dnsRecordsInCurrentOrder.Add(dnsChallenge.DnsRecordName);
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

                        if (existingRecords.Any(dnsRecord => dnsRecord.Content == dnsChallenge.DnsRecordValue))
                        {
                            appLogger.LogInformation("Already found a record that matches our challenge, ");
                        }
                        else
                        {
                            if (existingRecords.Count > 0 &&
                                !dnsRecordsInCurrentOrder.Contains(dnsChallenge.DnsRecordName))
                            {
                                appLogger.LogInformation(
                                    "Found existing records, but none matches our challenge, so we delete the old records");
                                await apiClient.DeleteDnsRecords(
                                    zone.Id,
                                    existingRecords.Select(dnsRecord => dnsRecord.Id));
                            }

                            var createdRecord = await apiClient.CreateDnsRecord(
                                zone,
                                dnsChallenge.DnsRecordName,
                                challengeRecordType,
                                content: dnsChallenge.DnsRecordValue,
                                3600);

                            appLogger.LogInformation("Created DNS record with ID {0}", createdRecord.Id);
                        }

                        dnsRecordsInCurrentOrder.Add(dnsChallenge.DnsRecordName);

                        appLogger.LogInformation("Answering challenge");

                        var updatedChallenge = await acmeClient.Acme.AnswerChallengeAsync(challenge.Url);

                        appLogger.LogInformation("Challenge is now in state {0}", updatedChallenge.Status);
                    }
                }

                var updatedAuthorization = await acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                appLogger.LogInformation("Authorization is now in state {0}", updatedAuthorization.Status);

                while (updatedAuthorization.Status == AcmeClient.Status.Pending)
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));

                    appLogger.LogInformation(
                        "Updating authorization {0}:{1}, because it is still pending",
                        updatedAuthorization.Identifier.Type,
                        updatedAuthorization.Identifier.Value);

                    updatedAuthorization = await acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                }

                appLogger.LogInformation("Authorization is final state {0}", updatedAuthorization.Status);
                authorizationResults.Add(updatedAuthorization);
            }

            if (authorizationResults.Any(authorization => authorization.Status != AcmeClient.Status.Valid))
            {
                appLogger.LogInformation("Some authorizations were invalid (see log above), aborting");
                return 4;
            }
        }

        appLogger.LogInformation("Updating order");
        order = await acmeClient.Acme.GetOrderDetailsAsync(order.OrderUrl, order);

        appLogger.LogInformation("Order is {0}", order.Payload.Status);

        var orderFolderName = new Uri(order.OrderUrl).LocalPath.Replace("/acme/order/", "").Replace("/", "_");
        var orderFolder = Path.Join(certbotConfiguration.Acme.StateDirectory, orderFolderName);
        if (!Directory.Exists(orderFolder))
        {
            Directory.CreateDirectory(orderFolder);
        }

        var keyFile = Path.Join(orderFolder, "keys.base64");

        PkiKeyPair? keyPair = null;
        if (order.Payload.Status == AcmeClient.Status.Ready)
        {
            appLogger.LogInformation("Generating keys and CSR");

            keyPair = keyAlgorithm switch
            {
                KeyAlgorithm.ECDSA => PkiKeyPair.GenerateEcdsaKeyPair(384),
                KeyAlgorithm.RSA => PkiKeyPair.GenerateRsaKeyPair(4096),
                _ => throw new ArgumentOutOfRangeException(nameof(keyAlgorithm))
            };

            var csr = new PkiCertificateSigningRequest($"CN={zoneName}", keyPair, PkiHashAlgorithm.Sha512);
            csr.CertificateExtensions.Add(PkiCertificateExtension.CreateDnsSubjectAlternativeNames(normalizedSANs));

            var keysAsBase64 = keyPair.ToBase64();
            if (File.Exists(keyFile))
            {
                appLogger.LogWarning("Keys already existed, and are overwritten");
                // TODO: Rename
            }

            await File.WriteAllTextAsync(keyFile, keysAsBase64);

            var binaryCsr = csr.ExportSigningRequest(PkiEncodingFormat.Der);

            order = await acmeClient.Acme.FinalizeOrderAsync(order.Payload.Finalize, binaryCsr);
            var x = 0;
        }

        if (order.Payload.Status == AcmeClient.Status.Valid)
        {
            appLogger.LogInformation("Order is valid");

            while (string.IsNullOrEmpty(order.Payload.Certificate))
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
                appLogger.LogInformation("Certificate not ready yet, refreshing");

                order = await acmeClient.Acme.GetOrderDetailsAsync(order.OrderUrl, order);
            }

            if (keyPair == null)
            {
                var stream = File.OpenRead(keyFile);
                keyPair = PkiKeyPair.Load(stream);
                stream.Close();
                await stream.DisposeAsync();
            }

            var certificateBytes = await acmeClient.Acme.GetOrderCertificateAsync(order);
        }

        var _ = 0;
    }
    catch (Exception ex)
    {
        appLogger.LogError(ex, "Error processing zone {0}", zoneName);
    }
}

return 0;