// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System.Threading.Tasks;
using PKISharp.SimplePKI;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public interface IPersistedOrder
    {
        string CertFile { get; }
        string PfxFile { get; }
        string PrivateKeyFile { get; }
        string PublicKeyFile { get; }

        Task SetKeyPair(PkiKeyPair keyPair);
        Task EnsureKeysLoadedAsync();
        Task ExportKeysAsync();
        Task ExportCertificateAsync(byte[] certificateBytes);
    }
}