// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using ACMESharp.Protocol;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public class Order
    {
        public OrderDetails Details { get; set; }
    }
}