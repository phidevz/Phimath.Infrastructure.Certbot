// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public class CloudflareError
    {
        public long? Code { get; set; }
        public string? Message { get; set; }
    }
}