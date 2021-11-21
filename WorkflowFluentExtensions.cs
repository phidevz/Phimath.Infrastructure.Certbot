// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Threading.Tasks;
using LanguageExt;
using LanguageExt.Common;

namespace Phimath.Infrastructure.Certbot
{
    public static class WorkflowFluentExtensions
    {
        public static Workflow CollectErrors(this Validation<Error, Workflow> input)
        {
            return input.IfFail(errors => throw new AggregateException(errors.Map(error => error.ToException()).ToArray()));
        }

        public static Task ProcessZones(this Task<Workflow> input)
        {
            return input.MapAsync(workflow => workflow.ProcessZones().ToUnit());
        }
    }
}