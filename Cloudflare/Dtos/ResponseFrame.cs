// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Collections.Generic;
using OLT.CloudFlare;

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public class ResponseFrame<T> where T : new()
    {
        public bool? Success { get; set; }

        public OltCloudFlareResultInfo ResultInfo { get; set; }

        public List<OltCloudFlareErrorElement> Errors { get; set; }

        public List<string> Messages { get; set; }

        public T Result { get; set; }
    }
}