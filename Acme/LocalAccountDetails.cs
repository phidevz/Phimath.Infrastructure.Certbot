// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.IO;
using System.Threading.Tasks;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public class LocalAccountDetails
    {
        private readonly string _accountDetailsFile;
        private readonly AccountDetails? _accountDetails;
        private readonly ILogger<LocalAccountDetails> _logger;

        private LocalAccountDetails(string accountDetailsFile,
            AccountDetails? accountDetails,
            ILogger<LocalAccountDetails> logger)
        {
            _accountDetailsFile = accountDetailsFile;
            _accountDetails = accountDetails;
            _logger = logger;
        }

        public async Task SaveAsync()
        {
            await File.WriteAllTextAsync(_accountDetailsFile, JsonConvert.SerializeObject(_accountDetails));
        }

        public static async Task<LocalAccountDetails> LoadOrCreateAsync(string stateDirectory,
            ILoggerFactory lf)
        {
            var logger = lf.CreateLogger<LocalAccountDetails>();

            var accountDetailsFile = Path.Join(stateDirectory, "10-AccountDetails.json");

            AccountDetails? accountDetails;
            if (File.Exists(accountDetailsFile))
            {
                logger.LogInformation("Loading existing account details");
                accountDetails =
                    JsonConvert.DeserializeObject<AccountDetails>(await File.ReadAllTextAsync(accountDetailsFile))!;
                logger.LogInformation("Existing account hast KID {0}", accountDetails.Kid);
            }
            else
            {
                accountDetails = null;
            }

            return new LocalAccountDetails(accountDetailsFile, accountDetails, logger);
        }
    }
}