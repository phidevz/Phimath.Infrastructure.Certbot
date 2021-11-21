// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Collections.Generic;
using System.Linq;
using Phimath.Infrastructure.Certbot.Configuration.Credentials.Cloudflare;
using Phimath.Infrastructure.Certbot.Configuration.Credentials.Zones;

namespace Phimath.Infrastructure.Certbot.Configuration
{
    public class CertbotConfiguration
    {
        public CloudflareCredential Credentials { get; init; }

        public Dictionary<string, Zone> Zones { get; init; }

        public AcmeConfiguration Acme { get; init; }

        public bool AreZonesValid =>
            Zones.All(zone => zone.Value.SANs?.TrueForAll(san => san.EndsWith(zone.Key)) ?? true);
    }
}