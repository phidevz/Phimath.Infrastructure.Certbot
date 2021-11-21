// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Linq;
using ACMESharp.Protocol.Resources;

namespace Phimath.Infrastructure.Certbot
{
    public static class FormatHelpers
    {
        public static string FormatAuthorizationError(this Authorization authorization) =>
            string.Format(
                "{0}:{1} ERROR {2}",
                authorization.Identifier.Type,
                authorization.Identifier.Value,
                string.Join(", ",
                    authorization.Challenges.DnsChallenges().Select(challenge => challenge.Error.ToString())));
    }
}