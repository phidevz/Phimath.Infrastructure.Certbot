// Copyright 2021 (c) phimath.
// All rights reserved if not stated otherwise or licensed under one or more agreements.
// If applicable, license agreements can be found in the top most level of the source repository.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;
using Phimath.Infrastructure.Certbot.Cloudflare.Dtos;
using Phimath.Infrastructure.Certbot.Configuration.Credentials.Cloudflare;
using RestSharp;
using RestSharp.Serializers.NewtonsoftJson;

namespace Phimath.Infrastructure.Certbot.Cloudflare
{
    public class ApiClient
    {
        private readonly string _authorizationHeader;
        private readonly string _baseUrl;

        private static readonly JsonSerializerSettings JsonSerializerSettings = new()
        {
            ContractResolver = new DefaultContractResolver
            {
                NamingStrategy = new SnakeCaseNamingStrategy()
            },
            NullValueHandling = NullValueHandling.Ignore,
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
            DateParseHandling = DateParseHandling.None,
            Converters =
            {
                new IsoDateTimeConverter { DateTimeStyles = DateTimeStyles.AssumeUniversal }
            },
        };

        public ApiClient(CloudflareCredential credential)
        {
            _baseUrl = "https://api.cloudflare.com/client/v4/";
            _authorizationHeader = $"Bearer {credential.Value}";
        }

        private async Task<T> ExecuteAsync<T>(IRestRequest request, string relativePath)
            where T : new()
        {
            var client = new RestClient
            {
                BaseUrl = new Uri(_baseUrl + relativePath),
            };
            client.UseNewtonsoftJson(JsonSerializerSettings);

            client.AddDefaultHeader(Headers.Authorization, _authorizationHeader);
            client.AddDefaultHeader("Content-Type", "application/json");

            var response = await client.ExecuteAsync<ResponseFrame<T>>(request);

            if (response.ErrorException != null)
            {
                throw response.ErrorException;
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new Exception($"HTTP/{response.StatusCode}: {response.Content}");
            }

            if (response.ResponseStatus != ResponseStatus.Completed)
            {
                throw new Exception($"Status: {response.ResponseStatus}. Message: {response.ErrorMessage}");
            }

            var cloudflareResponse = response.Data;

            if (cloudflareResponse.Success == true)
            {
                return cloudflareResponse.Result;
            }

            var cloudflareErrorBuilder = new StringBuilder();

            foreach (var error in cloudflareResponse.Errors)
            {
                cloudflareErrorBuilder.Append(error.Code.ToString()).Append(": ").AppendLine(error.Message);
            }

            throw new Exception(cloudflareErrorBuilder.ToString());
        }

        public async Task<IReadOnlyList<Zone>> GetZones(string? name = null, int page = 1,
            int pageSize = 50)
        {
            var request = new RestRequest(Method.GET)
                .AddParameter(CommonParameters.Page, page)
                .AddParameter(CommonParameters.PageSize, pageSize);

            if (!string.IsNullOrWhiteSpace(name))
            {
                request.AddParameter(CommonParameters.Name, name);
            }

            return await ExecuteAsync<List<Zone>>(request, "zones");
        }

        public async Task<IReadOnlyList<DnsRecord>> GetDnsRecords(IZoneNameAndId zoneNameAndId,
            string? name = null,
            DnsRecordTypes dnsRecordTypes = DnsRecordTypes.ALL,
            int page = 1,
            int pageSize = 50)
        {
            var request = new RestRequest(Method.GET)
                .AddParameter(CommonParameters.Page, page)
                .AddParameter(CommonParameters.PageSize, pageSize);

            if (!string.IsNullOrWhiteSpace(name))
            {
                request.AddParameter(CommonParameters.Name, $"{name}.{zoneNameAndId.Name}");
            }

            if (dnsRecordTypes != DnsRecordTypes.ALL)
            {
                request.AddParameter(CommonParameters.Type, dnsRecordTypes.ToString().ToUpperInvariant());
            }

            return await ExecuteAsync<List<DnsRecord>>(request, $"zones/{zoneNameAndId.Id}/dns_records");
        }

        public async Task<Zone?> GetZone(string name)
        {
            var zones = await GetZones(name);
            return zones.Count > 0 ? zones[0] : null;
        }
    }
}