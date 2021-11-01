// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.IO;
using System.Threading.Tasks;
using ACMESharp.Crypto;
using ACMESharp.Crypto.JOSE;
using ACMESharp.Crypto.JOSE.Impl;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public class LocalAccountKey
    {
        private readonly string _serviceDirectoryFile;
        private AccountKey? _accountKey;
        private readonly ILogger<LocalAccountKey> _logger;

        public bool IsUninitialized => _accountKey == null;

        private LocalAccountKey(string serviceDirectoryFile, AccountKey? accountKey, IJwsTool? signer,
            ILogger<LocalAccountKey> logger)
        {
            Signer = signer;
            _serviceDirectoryFile = serviceDirectoryFile;
            _accountKey = accountKey;
            _logger = logger;
        }

        public IJwsTool? Signer { get; private set; }

        public async Task SaveAsync()
        {
            await File.WriteAllTextAsync(_serviceDirectoryFile, JsonConvert.SerializeObject(_accountKey));
        }

        public static async Task<LocalAccountKey> LoadAsync(string stateDirectory, ILoggerFactory lf)
        {
            var logger = lf.CreateLogger<LocalAccountKey>();

            var accountKeyFile = Path.Join(stateDirectory, "15-AccountKey.json");

            AccountKey? accountKey;
            IJwsTool? signer;

            if (File.Exists(accountKeyFile))
            {
                logger.LogInformation("Loading existing service directory");
                accountKey =
                    JsonConvert.DeserializeObject<AccountKey>(await File.ReadAllTextAsync(accountKeyFile))!;

                if (accountKey.Algorithm.StartsWith("ES"))
                {
                    var esTool = new ESJwsTool();
                    esTool.HashSize = int.Parse(accountKey.Algorithm[2..]);
                    signer = esTool;
                }
                else if (accountKey.Algorithm.StartsWith("RS"))
                {
                    var rsTool = new RSJwsTool();
                    rsTool.HashSize = int.Parse(accountKey.Algorithm[2..]);
                    signer = rsTool;
                }
                else
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(accountKey.Algorithm),
                        accountKey.Algorithm,
                        "Unknown algorithm type");
                }

                signer.Init();
                signer.Import(accountKey.Export);
            }
            else
            {
                accountKey = null;
                signer = null;
            }

            return new LocalAccountKey(accountKeyFile, accountKey, signer, logger);
        }

        public void SetFromSigner(IJwsTool acmeSigner)
        {
            Signer = acmeSigner;
            _accountKey = new AccountKey
            {
                Algorithm = acmeSigner.JwsAlg,
                Export = acmeSigner.Export()
            };
        }
    }
}