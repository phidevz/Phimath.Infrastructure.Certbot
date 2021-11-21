// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LanguageExt;
using PKISharp.SimplePKI;

namespace Phimath.Infrastructure.Certbot.Acme
{
    public class PersistedOrder : IPersistedOrder
    {
        private readonly string _keyFile;
        private readonly string _certFile;
        private readonly string _pfxFile;
        private readonly string _privateKeyFile;
        private readonly string _publicKeyFile;

        private Option<PkiKeyPair> _keyPair = Option<PkiKeyPair>.None;

        public PersistedOrder(string orderFolder, string zoneName)
        {
            _keyFile = Path.Join(orderFolder, "keys.dat");
            _certFile = Path.Join(orderFolder, $"{zoneName}.crt");
            _pfxFile = Path.Join(orderFolder, $"{zoneName}.pfx");
            _privateKeyFile = Path.Join(orderFolder, $"{zoneName}.key");
            _publicKeyFile = Path.Join(orderFolder, $"{zoneName}.pubkey");
        }

        public async Task SetKeyPair(PkiKeyPair keyPair)
        {
            _keyPair = keyPair;

            var writeStream = File.Open(_keyFile, FileMode.Create, FileAccess.Write);
            keyPair.Save(writeStream);
            await writeStream.FlushAsync();
            await writeStream.DisposeAsync();
        }

        public Task ExportKeysAsync() =>
            _keyPair.Map(async keyPair =>
                {
                    await File.WriteAllBytesAsync(_privateKeyFile, keyPair.PrivateKey.Export(PkiEncodingFormat.Pem));
                    await File.WriteAllBytesAsync(_publicKeyFile, keyPair.PublicKey.Export(PkiEncodingFormat.Pem));
                })
                .IfNone(Task.FromException(new Exception("Key pair not loaded!")));

        public async Task ExportCertificateAsync(byte[] certificateBytes)
        {
            await File.WriteAllBytesAsync(_certFile, certificateBytes);

            var pkiCert = PkiCertificate.From(new X509Certificate2(certificateBytes));
            await _keyPair.Map(async keyPair =>
                {
                    await File.WriteAllBytesAsync(_pfxFile,
                        pkiCert.Export(PkiArchiveFormat.Pkcs12, keyPair.PrivateKey));
                })
                .IfNone(Task.FromException(new Exception("Key pair not loaded!")));
        }

        public async Task EnsureKeysLoadedAsync()
        {
            if (_keyPair.IsSome)
            {
                return;
            }

            var stream = File.OpenRead(_keyFile);
            _keyPair = PkiKeyPair.Load(stream);
            stream.Close();
            await stream.DisposeAsync();
        }
    }
}