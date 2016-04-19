﻿using System;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using System.Collections;

namespace OAuth2.Client.Impl
{
    public class DigitalOceanClient : OAuth2Client
    {
        private string _accessToken;

        /// <summary>
        /// Initializes a new instance of the <see cref="DigitalOceanClient"/> class.
        /// </summary>
        /// <param name="factory">The factory.</param>
        /// <param name="configuration">The configuration.</param>
        /// <param name="persistor">Object to store token info between instantiations (e.g. web requests - <see cref="SessionPersistor"/>)</param>
        public DigitalOceanClient(IRequestFactory factory, IClientConfiguration configuration, IDictionary persistor = null)
            : base(factory, configuration, persistor)
        {
        }

        public override string Name
        {
            get { return "DigitalOcean"; }
        }

        protected override Endpoint AccessCodeServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://cloud.digitalocean.com",
                    Resource = "/v1/oauth/authorize"
                };
            }
        }

        protected override void AfterGetAccessToken(BeforeAfterRequestArgs args)
        {
             _accessToken = args.Response.Content;
        }

        protected override Endpoint AccessTokenServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://cloud.digitalocean.com",
                    Resource = "/v1/oauth/token"
                };
            }
        }

        protected override Endpoint UserInfoServiceEndpoint
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override UserInfo GetUserInfo()
        {
            return ParseUserInfo(_accessToken);
        }

        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            return new UserInfo
            {
                Id = response["uid"].Value<string>(),
                FirstName = response["info"]["name"].Value<string>(),
                LastName = "",
                Email = response["info"]["email"].SafeGet(x => x.Value<string>())
            };
        }
    }
}
