// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Diagnostics.CodeAnalysis;

namespace Phimath.Infrastructure.Certbot.Cloudflare
{
    [Flags]
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public enum DnsRecordTypes
    {
        A,
        AAAA,
        CNAME,
        HTTPS,
        TXT,
        SRV,
        LOC,
        MX,
        NS,
        CERT,
        DNSKEY,
        DS,
        NAPTR,
        SMIMEA,
        SSHFP,
        SVCB,
        TLSA,
        URI,

        ALL = A | AAAA | CNAME | HTTPS | TXT | SRV | LOC | MX | NS | CERT | DNSKEY | DS | NAPTR | SMIMEA | SSHFP |
              SVCB | TLSA | URI
    }
}