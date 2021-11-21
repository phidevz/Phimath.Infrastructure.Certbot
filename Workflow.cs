// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using DnsClient;
using LanguageExt;
using LanguageExt.Common;
using Microsoft.Extensions.Logging;
using Phimath.Infrastructure.Certbot.Acme;
using Phimath.Infrastructure.Certbot.Cloudflare;
using Phimath.Infrastructure.Certbot.Cloudflare.Dtos;
using Phimath.Infrastructure.Certbot.Configuration;
using PKISharp.SimplePKI;
using Zone = Phimath.Infrastructure.Certbot.Configuration.Credentials.Zones.Zone;

namespace Phimath.Infrastructure.Certbot
{
    public class Workflow
    {
        // Max retries: 60 * 2 seconds delay = 120 seconds of trying, should be enough
        private const int MaxRetries = 60;

        private readonly CertbotConfiguration _configuration;
        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger<Workflow> _logger;
        private AcmeClient _acmeClient;
        private ApiClient _apiClient;
        private KeyAlgorithm _keyAlgorithm;
        private Seq<Validation<Error, KeyValuePair<string, Zone>>> _zones;

        internal static Workflow Configure(CertbotConfiguration configuration, ILoggerFactory loggerFactory)
        {
            return new Workflow(configuration, loggerFactory);
        }

        private Workflow(CertbotConfiguration configuration, ILoggerFactory loggerFactory)
        {
            _configuration = configuration;
            _loggerFactory = loggerFactory;
            _logger = loggerFactory.CreateLogger<Workflow>();
        }

        public Validation<Error, Workflow> ValidateConfiguration()
        {
            return ValidateKeyAlgorithm()
                   | ValidateZones();
        }

        private Validation<Error, Workflow> ValidateZones()
        {
            _zones = _configuration.Zones.Map(Utils.ValidateZone).ToSeq();
            // TODO
            return this;
        }

        private Validation<Error, Workflow> ValidateKeyAlgorithm()
        {
            switch (_configuration.Acme.KeyAlgorithm)
            {
                case KeyAlgorithm.Invalid:
                {
                    return Error.New(5, "KeyAlgorithm is invalid, can only be ECDSA or RSA");
                }
                case null:
                    _keyAlgorithm = KeyAlgorithm.ECDSA;
                    break;
                default:
                    _keyAlgorithm = _configuration.Acme.KeyAlgorithm.Value;
                    break;
            }

            return this;
        }

        public async Task<Workflow> InitClients()
        {
            _acmeClient = await AcmeClient.CreateAsync(_configuration.Acme, _loggerFactory);
            _apiClient = new ApiClient(_configuration.Credentials);

            return this;
        }

        public async Task ProcessZones()
        {
            foreach (var zoneValidation in _zones)
            {
                switch (zoneValidation.Case)
                {
                    case Seq<Error> errors:
                    {
                        foreach (var error in errors)
                        {
                            _logger.LogError("Configuration error: {0}", error.Message);
                        }

                        break;
                    }
                    case KeyValuePair<string, Zone> zoneInfo:
                    {
                        zoneInfo.Deconstruct(out var zoneName, out var zoneConfiguration);
                        try
                        {
                            await ProcessZone(zoneName, zoneConfiguration);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error processing zone {ZoneName}", zoneName);
                        }
                        finally
                        {
                            _logger.LogInformation("Finished processing zone {ZoneName}", zoneName);
                        }

                        break;
                    }
                }
            }
        }

        private async Task ProcessZone(string zoneName, Zone zoneConfiguration)
        {
            _logger.LogInformation("Processing zone {ZoneName}", zoneName);
            _logger.LogInformation("Getting zone information from Cloudflare");

            var zone = await _apiClient.GetZone(zoneName);
            if (zone == null)
            {
                _logger.LogError("Zone {ZoneName} not exist", zoneName);
                return;
            }

            _logger.LogInformation("Zone {ZoneName} has ID {ZoneId}", zoneName, zone.Id);
            _logger.LogInformation("Now performing ACME actions");

            var normalizedSANs = zoneConfiguration.SANs
                .PrependWhen(zoneName, zoneConfiguration.IncludeZoneNameAsSAN)
                .Distinct()
                .ToImmutableList();

            if (!normalizedSANs.Any())
            {
                _logger.LogError(
                    "At least one SAN must be specified for zone {ZoneName}, or the zone must be included as a SAN",
                    zoneName);
                return;
            }

            var order = await _acmeClient.CreateOrderAsync(zoneName, normalizedSANs);
            if (order.Payload.Status == AcmeClient.Status.Pending)
            {
                _logger.LogInformation("Processing authorizations of order {OrderUrl} for zone {ZoneName}",
                    order.OrderUrl, zoneName);

                var authorizationResults = new List<Authorization>(order.Payload.Authorizations.Length);
                var dnsRecordsInCurrentOrder = new System.Collections.Generic.HashSet<string>();

                foreach (var authorizationUrl in order.Payload.Authorizations)
                {
                    var authorization = await _acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                    _logger.LogInformation(
                        "Processing authorization for {0}:{1} with {2} challenge(s), initial status {3}",
                        authorization.Identifier.Type,
                        authorization.Identifier.Value,
                        authorization.Challenges.Length,
                        authorization.Status);

                    foreach (var challenge in authorization.Challenges)
                    {
                        await ProcessChallenge(zoneName, zone, challenge, authorization, dnsRecordsInCurrentOrder);
                    }

                    var updatedAuthorization = await _acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                    _logger.LogInformation("Authorization is now in state {AuthorizationStatus}",
                        updatedAuthorization.Status);

                    while (updatedAuthorization.Status == AcmeClient.Status.Pending)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5));

                        _logger.LogInformation(
                            "Updating authorization {IdentifierType}:{IdentifierValue}, because it is still pending",
                            updatedAuthorization.Identifier.Type,
                            updatedAuthorization.Identifier.Value);

                        updatedAuthorization = await _acmeClient.Acme.GetAuthorizationDetailsAsync(authorizationUrl);
                    }

                    _logger.LogInformation("Authorization is final state {AuthorizationStatus}",
                        updatedAuthorization.Status);
                    authorizationResults.Add(updatedAuthorization);
                }

                var errors = authorizationResults
                    .Where(authorization => authorization.Status != AcmeClient.Status.Valid)
                    .Select(FormatHelpers.FormatAuthorizationError)
                    .ToSeq();

                if (errors.Any())
                {
                    _logger.LogInformation(
                        "Some authorizations were invalid (see below), aborting processing for this zone");
                    // ReSharper disable once TemplateIsNotCompileTimeConstantProblem
                    errors.Iter(error => _logger.LogError(error));

                    return;
                }
            }

            _logger.LogInformation("Updating order");
            order = await _acmeClient.Acme.GetOrderDetailsAsync(order.OrderUrl, order);

            _logger.LogInformation("Order is {OrderStatus}", order.Payload.Status);

            var persistedOrder = _acmeClient.PersistOrder(zoneName, NormalizeOrderUrl(order));

            if (order.Payload.Status == AcmeClient.Status.Ready)
            {
                _logger.LogInformation("Generating keys and CSR");

                var keyPair = _keyAlgorithm switch
                {
                    KeyAlgorithm.ECDSA => PkiKeyPair.GenerateEcdsaKeyPair(384),
                    KeyAlgorithm.RSA => PkiKeyPair.GenerateRsaKeyPair(4096),
                    _ => throw new ArgumentOutOfRangeException(nameof(_keyAlgorithm))
                };

                var csr = new PkiCertificateSigningRequest($"CN={normalizedSANs.First()}", keyPair,
                    PkiHashAlgorithm.Sha512);
                csr.CertificateExtensions.Add(PkiCertificateExtension.CreateDnsSubjectAlternativeNames(normalizedSANs));

                await persistedOrder.SetKeyPair(keyPair);

                var binaryCsr = csr.ExportSigningRequest(PkiEncodingFormat.Der);

                order = await _acmeClient.Acme.FinalizeOrderAsync(order.Payload.Finalize, binaryCsr);
            }

            if (order.Payload.Status == AcmeClient.Status.Valid)
            {
                _logger.LogInformation("Order is valid");

                while (string.IsNullOrEmpty(order.Payload.Certificate))
                {
                    await Task.Delay(TimeSpan.FromSeconds(5));
                    _logger.LogInformation("Certificate not ready yet, refreshing");

                    order = await _acmeClient.Acme.GetOrderDetailsAsync(order.OrderUrl, order);
                }

                await persistedOrder.EnsureKeysLoadedAsync();

                _logger.LogInformation("Exporting key material");
                await persistedOrder.ExportKeysAsync();

                _logger.LogInformation("Getting certificate and storing locally");
                var certificateBytes = await _acmeClient.Acme.GetOrderCertificateAsync(order);
                await persistedOrder.ExportCertificateAsync(certificateBytes);
            }
        }

        private static string NormalizeOrderUrl(OrderDetails? order)
        {
            return new Uri(order.OrderUrl).LocalPath.Replace("/acme/order/", "").Replace("/", "-");
        }

        private async Task ProcessChallenge(string zoneName, IZoneNameAndId zone, Challenge challenge,
            Authorization authorization, ISet<string> dnsRecordsInCurrentOrder)
        {
            if (!challenge.IsDnsChallenge())
            {
                _logger.LogDebug("Skipping non-DNS challenge of type {ChallengeType}", challenge.Type);
                return;
            }

            var dnsChallenge = AuthorizationDecoder.ResolveChallengeForDns01(
                authorization,
                challenge,
                _acmeClient.Signer);

            await HandleDnsChallenge(zoneName, zone, challenge, dnsRecordsInCurrentOrder, dnsChallenge);
        }

        private async Task HandleDnsChallenge(string zoneName, IZoneNameAndId zone, Challenge challenge,
            ISet<string> dnsRecordsInCurrentOrder, Dns01ChallengeValidationDetails dnsChallenge)
        {
            _logger.LogInformation(
                "DNS challenge is: [{RecordName}] {RecordType}={RecordValue}",
                dnsChallenge.DnsRecordName,
                dnsChallenge.DnsRecordType,
                dnsChallenge.DnsRecordValue);

            if (challenge.Status != AcmeClient.Status.Pending)
            {
                _logger.LogWarning(
                    "Challenge is {ChallengeStatus}, but expected status was {ExpectedStatus}",
                    challenge.Status,
                    AcmeClient.Status.Pending);

                dnsRecordsInCurrentOrder.Add(dnsChallenge.DnsRecordName);
            }
            else
            {
                await HandlePendingChallenge(zoneName, zone, challenge, dnsRecordsInCurrentOrder, dnsChallenge);
            }
        }

        private async Task HandlePendingChallenge(string zoneName, IZoneNameAndId zone, Challenge challenge,
            ISet<string> dnsRecordsInCurrentOrder, Dns01ChallengeValidationDetails dnsChallenge)
        {
            if (!Enum.TryParse(dnsChallenge.DnsRecordType, true,
                out DnsRecordTypes challengeRecordType))
            {
                _logger.LogWarning(
                    "Challenge requested unsupported DNS record type {RecordType}, falling back to TXT",
                    dnsChallenge.DnsRecordType);
                challengeRecordType = DnsRecordTypes.TXT;
            }

            _logger.LogInformation("Checking for existing challenges in zone {ZoneName}", zoneName);

            var existingRecords = await _apiClient.GetDnsRecords(
                zone,
                dnsChallenge.DnsRecordName,
                challengeRecordType);

            _logger.LogInformation(
                "Found {ExistingRecords} existing record(s) for that challenge type and name",
                existingRecords.Count);

            if (existingRecords.Any(dnsRecord => dnsRecord.Content == dnsChallenge.DnsRecordValue))
            {
                _logger.LogInformation("Already found a record that matches our challenge, ");
            }
            else
            {
                if (existingRecords.Count > 0 &&
                    !dnsRecordsInCurrentOrder.Contains(dnsChallenge.DnsRecordName))
                {
                    _logger.LogInformation(
                        "Found existing records, but none matches our challenge, so we delete the old records");
                    await _apiClient.DeleteDnsRecords(
                        zone.Id,
                        existingRecords.Select(dnsRecord => dnsRecord.Id));
                }

                var createdRecord = await _apiClient.CreateDnsRecord(
                    zone,
                    dnsChallenge.DnsRecordName,
                    challengeRecordType,
                    dnsChallenge.DnsRecordValue,
                    120);

                _logger.LogInformation("Created DNS record with ID {RecordId}", createdRecord.Id);

                await ChallengeSuccessOrTimeout(dnsChallenge);
            }

            dnsRecordsInCurrentOrder.Add(dnsChallenge.DnsRecordName);

            _logger.LogInformation("Answering challenge");

            var updatedChallenge = await _acmeClient.Acme.AnswerChallengeAsync(challenge.Url);

            _logger.LogInformation("Challenge is now in state {ChallengeStatus}",
                updatedChallenge.Status);
        }

        private async Task ChallengeSuccessOrTimeout(Dns01ChallengeValidationDetails dnsChallenge)
        {
            var dnsClient = new LookupClient(new LookupClientOptions(NameServer.Cloudflare, NameServer.Cloudflare2)
                { UseCache = false });

            var retries = 0;
            bool challengeFound;

            bool IsChallengeSuccess(string recordContent)
                => recordContent == dnsChallenge.DnsRecordValue;

            do
            {
                var queryResult = await dnsClient.QueryAsync(dnsChallenge.DnsRecordName, QueryType.TXT);

                challengeFound = queryResult.Answers
                    .TxtRecords()
                    .Any(txtRecord => txtRecord.Text.Any(IsChallengeSuccess));

                _logger.LogInformation("Challenge not yet found, retrying in 2 seconds");

                await Task.Delay(TimeSpan.FromSeconds(2));
            } while (!challengeFound && retries++ < MaxRetries);

            // To be extra sure, add another 1 seconds
            await Task.Delay(TimeSpan.FromSeconds(1));
        }
    }
}