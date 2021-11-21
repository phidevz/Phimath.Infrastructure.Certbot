// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol.Resources;
using LanguageExt;
using LanguageExt.Common;
using Phimath.Infrastructure.Certbot.Configuration.Credentials.Zones;
using PKISharp.SimplePKI;

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

        public static Validation<Error, KeyValuePair<string, Zone>> ValidateZone(KeyValuePair<string, Zone> zoneInfo)
        {
            var errors = zoneInfo.Value.SANs.ToSeq().Filter(san => !san.EndsWith(zoneInfo.Key))
                .Map(san => Error.New($"SAN '{san}' is not a subdomain"));

            return errors.IsEmpty ? zoneInfo : errors;
        }

        public static string ToBase64(this PkiKeyPair keyPair)
        {
            using var stream = new MemoryStream();
            keyPair.Save(stream);
            return Convert.ToBase64String(stream.ToArray());
        }

        public static IEnumerable<TSource> PrependWhen<TSource>(this IEnumerable<TSource> source,
            TSource element,
            bool when) =>
            when ? source.Prepend(element) : source;

        public static IEnumerable<Challenge> DnsChallenges(this IEnumerable<Challenge> challenges)
            => challenges.Where(IsDnsChallenge);

        public static bool IsDnsChallenge(this Challenge challenge)
            => challenge.Type == Dns01ChallengeValidationDetails.Dns01ChallengeType;

        public static Task<Validation<TFail, TResult>> MapAsync<TFail, TSuccess, TResult>(
            this Validation<TFail, TSuccess> self,
            Func<TSuccess, Task<TResult>> asyncTransform)
        {
            return self.MatchAsync(
                async success => Validation<TFail, TResult>.Success(await asyncTransform(success)),
                errors => Validation<TFail, TResult>.Fail(errors));
        }

        public static Task<Validation<TFail, TResult>> MapAsync<TFail, TSuccess, TResult>(
            this Task<Validation<TFail, TSuccess>> self,
            Func<TSuccess, Task<TResult>> asyncTransform)
        {
            return self.MapAsync(validation => validation.MapAsync(asyncTransform));
        }
    }
}