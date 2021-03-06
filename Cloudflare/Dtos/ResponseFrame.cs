// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

namespace Phimath.Infrastructure.Certbot.Cloudflare.Dtos
{
    public class ResponseFrame<T> where T : new()
    {
        public bool? Success { get; set; }

        public CloudflareResultInfo ResultInfo { get; set; }

        public CloudflareError[] Errors { get; set; }

        public string[] Messages { get; set; }

        public T Result { get; set; }
    }
}