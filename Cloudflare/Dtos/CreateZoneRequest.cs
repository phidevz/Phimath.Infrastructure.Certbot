// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public class CreateZoneRequest
    {
        public string Type { get; set; }
        public string Name { get; set; }
        public string Content { get; set; }
        public int Ttl { get; set; }
    }
}