// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Collections.Generic;

namespace Phimath.Infrastructure.Certbot.Configuration.Credentials.Zones
{
    public class Zone
    {
        // ReSharper disable once InconsistentNaming
        public List<string> AdditionalSANs { get; set; } = new();
    }
}