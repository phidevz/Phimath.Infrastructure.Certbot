// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public interface IZoneNameAndId
    {
        public string Id { get; }

        public string Name { get; }
    }

    public class Zone : IZoneNameAndId
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public long? DevelopmentMode { get; set; }

        public string[] OriginalNameServers { get; set; }

        public string OriginalRegistrar { get; set; }

        public string OriginalDnshost { get; set; }

        public DateTimeOffset? CreatedOn { get; set; }

        public DateTimeOffset? ModifiedOn { get; set; }

        public DateTimeOffset? ActivatedOn { get; set; }

        public string[] Permissions { get; set; }

        public string Status { get; set; }

        public bool? Paused { get; set; }

        public string Type { get; set; }

        public string[] NameServers { get; set; }

        public Zone()
        {
        }
    }
}