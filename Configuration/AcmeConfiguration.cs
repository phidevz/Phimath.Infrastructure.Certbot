// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Collections.Generic;

namespace Phimath.Infrastructure.Certbot.Configuration
{
    public class AcmeConfiguration
    {
        public bool UseStaging { get; set; } = false;
        public string StateDirectory { get; set; }

        public string[] AccountEmails { get; set; }
        
        public KeyAlgorithm? KeyAlgorithm { get; set; }
        
        public int? KeySize { get; set; }
    }
}