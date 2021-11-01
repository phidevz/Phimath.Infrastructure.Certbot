// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Phimath.Infrastructure.Certbot
{
    public static class Utils
    {
        public static async Task<TOut> AndThen<TIn, TOut>(this Task<TIn> self, Func<TIn, TOut> transform)
        {
            return transform(await self);
        }

        public static async Task AndThen<TIn>(this Task<TIn> self, Action<TIn> consumer)
        {
            consumer(await self);
        }

        public static bool IsZoneValid(string zoneName, IEnumerable<string> sans)
        {
            return sans.All(san => san.EndsWith(zoneName));
        }
    }
}