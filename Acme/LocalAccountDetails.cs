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
        private readonly string _serviceDirectoryFile;
        private readonly ServiceDirectory _serviceDirectory;
        private readonly ILogger<LocalAccountDetails> _logger;

        private LocalAccountDetails(string serviceDirectoryFile, ServiceDirectory serviceDirectory,
            ILogger<LocalAccountDetails> logger)
        {
            _serviceDirectoryFile = serviceDirectoryFile;
            _serviceDirectory = serviceDirectory;
            _logger = logger;
        }

        public async Task SaveAsync()
        {
            await File.WriteAllTextAsync(_serviceDirectoryFile, JsonConvert.SerializeObject(_serviceDirectory));
        }

        public static async Task<LocalAccountDetails> LoadOrCreateAsync(string stateDirectory,
            bool refreshServiceDirectory, ILoggerFactory lf, AcmeProtocolClient acme)
        {
            var logger = lf.CreateLogger<LocalAccountDetails>();

            var serviceDirectoryFile = Path.Join(stateDirectory, "00-ServiceDirectory.json");

            bool shallSave = false;

            ServiceDirectory serviceDirectory;
            if (File.Exists(serviceDirectoryFile) && !refreshServiceDirectory)
            {
                logger.LogInformation("Loading existing service directory");
                serviceDirectory =
                    JsonConvert.DeserializeObject<ServiceDirectory>(await File.ReadAllTextAsync(serviceDirectoryFile))!;
            }
            else
            {
                logger.LogInformation("Refreshing service directory");
                serviceDirectory = await acme.GetDirectoryAsync();
                acme.Directory = serviceDirectory;

                shallSave = true;
            }

            var result = new LocalAccountDetails(serviceDirectoryFile, serviceDirectory, logger);

            if (shallSave)
            {
                await result.SaveAsync();
            }

            return result;
        }
    }
}