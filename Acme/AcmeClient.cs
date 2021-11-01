// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Microsoft.Extensions.Logging;
using Phimath.Infrastructure.Certbot.Cloudflare.Dtos;
using Phimath.Infrastructure.Certbot.Configuration;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public sealed class AcmeClient : IDisposable
    {
        public static class Status
        {
            public const string Valid = "valid";
            public const string Invalid = "invalid";
            public const string Pending = "pending";
        }


        private readonly AcmeConfiguration _configuration;
        private readonly ILogger<AcmeClient> _logger;
        private readonly LocalServiceDirectory _serviceDirectory;
        private readonly LocalAccountDetails _accountDetails;
        private readonly LocalAccountKey _accountKey;

        private AcmeClient(AcmeConfiguration configuration,
            ILogger<AcmeClient> logger,
            AcmeProtocolClient acme,
            LocalServiceDirectory serviceDirectory,
            LocalAccountDetails accountDetails,
            LocalAccountKey accountKey)
        {
            _configuration = configuration;
            _logger = logger;
            Acme = acme;
            _serviceDirectory = serviceDirectory;
            _accountDetails = accountDetails;
            _accountKey = accountKey;
        }

        public IJwsTool? Signer => _accountKey.Signer;
        public AcmeProtocolClient Acme { get; }

        public async Task<OrderDetails> CreateOrderAsync(string zoneName, IReadOnlyList<string> additionalSANs)
        {
            var order = await Acme.CreateOrderAsync(additionalSANs.Prepend(zoneName).Distinct());
            if (order.Payload.Status == Status.Invalid)
            {
                throw new Exception($"Order {order.OrderUrl} is already marked as invalid after creation");
            }

            _logger.LogInformation("Created order at {0}, expires {1}, initial status {2}", order.OrderUrl,
                order.Payload.Expires, order.Payload.Status);

            return order;
        }

        public static async Task<AcmeClient> CreateAsync(AcmeConfiguration configuration, ILoggerFactory lf)
        {
            var logger = lf.CreateLogger<AcmeClient>();

            if (!Directory.Exists(configuration.StateDirectory))
            {
                logger.LogWarning("State directory '{0}' does not exist, so it will be created",
                    configuration.StateDirectory);
                Directory.CreateDirectory(configuration.StateDirectory);
            }

            var acmeBaseUri = configuration.UseStaging
                ? new Uri("https://acme-staging-v02.api.letsencrypt.org/")
                : new Uri("https://acme-v02.api.letsencrypt.org/");

            var accountDetails = await LocalAccountDetails.LoadAsync(configuration.StateDirectory, lf);
            var accountKey = await LocalAccountKey.LoadAsync(configuration.StateDirectory, lf);

            var acme = new AcmeProtocolClient(
                acmeBaseUri,
                acct: accountDetails.AccountDetails,
                signer: accountKey.Signer,
                logger: lf.CreateLogger<AcmeProtocolClient>(),
                usePostAsGet: true);

            var serviceDirectory = await LocalServiceDirectory.LoadOrCreateAsync(
                configuration.StateDirectory,
                false,
                lf,
                acme);

            await acme.GetNonceAsync();

            if (accountDetails.IsUninitialized || accountKey.IsUninitialized)
            {
                logger.LogInformation("Registering new account");
                if (configuration.AccountEmails.Length == 0)
                {
                    throw new Exception("You need to specify at least one contact email for an ACME account");
                }

                var signer = await accountDetails.CreateNewAccountAsync(configuration.AccountEmails, acme);
                accountKey.SetFromSigner(signer);

                await accountDetails.SaveAsync();
                await accountKey.SaveAsync();
            }

            return new AcmeClient(configuration, logger, acme, serviceDirectory, accountDetails, accountKey);
        }

        public void Dispose()
        {
            Acme.Dispose();
        }
    }
}