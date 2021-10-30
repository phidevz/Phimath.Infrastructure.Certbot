// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public record DnsRecord
    {
        public DnsRecord()
        {
        }

        public string Id { get; init; }
        public string ZoneId { get; init; }
        public string ZoneName { get; init; }
        public string Name { get; init; }
        public string Type { get; init; }
        public string Content { get; init; }
        public bool Proxiable { get; init; }
        public bool Proxied { get; init; }
        public int Ttl { get; init; }
        public DateTimeOffset CreateOn { get; init; }
        public DateTimeOffset ModifiedOn { get; init; }
    }
}