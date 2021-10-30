// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Phimath.Infrastructure.Certbot.Configuration;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public class AcmeClient : IDisposable
    {
        private readonly AcmeConfiguration _configuration;
        private readonly ILogger<AcmeClient> _logger;
        private readonly HttpClient _acmeBaseClient;

        private static class StateFiles
        {
            public const string ServiceDirectory = "00-ServiceDirectory.json";
            public const string AccountDetails = "10-AccountDetails.json";
            public const string AccountKey = "15-AccountKey.json";
        }

        private AcmeClient(AcmeConfiguration configuration, ILogger<AcmeClient> logger, HttpClient acmeBaseClient)
        {
            _configuration = configuration;

            _logger = logger;
            _acmeBaseClient = acmeBaseClient;
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

            var acmeBaseClient = new HttpClient()
            {
                BaseAddress = 
            }
            
            var acme = new AcmeProtocolClient();
            var serviceDirectory = await LocalServiceDirectory.LoadOrCreateAsync(
                configuration.StateDirectory,
                false,
                lf,
                acme);

            var accountDetailsFile = Path.Join(configuration.StateDirectory, StateFiles.AccountDetails);
            AccountDetails? accountDetails;
            if (File.Exists(accountDetailsFile))
            {
                logger.LogInformation("Loading existing account details");
                accountDetails =
                    JsonConvert.DeserializeObject<AccountDetails>(File.ReadAllText(accountDetailsFile))!;
                logger.LogInformation("Existing account hast KID {0}", accountDetails.Kid);
            }
            else
            {
                accountDetails = null;
            }

            return new AcmeClient(configuration, logger, acmeBaseClient);
        }
    }
}