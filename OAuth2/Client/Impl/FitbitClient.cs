using System.Linq;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp.Authenticators;
using System;
using RestSharp;
using System.Collections;

namespace OAuth2.Client.Impl
{
    /// <summary>
    /// Instagram authentication client.
    /// </summary>
    public class FitbitClient : OAuth2Client
    {

        public FitbitClient(IRequestFactory factory, IClientConfiguration configuration) : this(factory, configuration, null) { }
        /// <summary>
        /// Initializes a new instance of the <see cref="FitbitClient"/> class.
        /// </summary>
        /// <param name="factory">The factory.</param>
        /// <param name="configuration">The configuration.</param>
        public FitbitClient(IRequestFactory factory, IClientConfiguration configuration, IDictionary persistor)
            : base(factory, configuration, persistor)
        {
        }

        /// <summary>
        /// Defines URI of service which issues access code.
        /// </summary>
        protected override Endpoint AccessCodeServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://www.fitbit.com",
                    Resource = "/oauth2/authorize"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which issues access token.
        /// </summary>
        protected override Endpoint AccessTokenServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://api.fitbit.com",
                    Resource = "/oauth2/token"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which allows to obtain information about user which is currently logged in.
        /// </summary>
        protected override Endpoint UserInfoServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://api.fitbit.com",
                    Resource = "/1/user/-/profile.json"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which allows to obtain information about intra-day step data.
        /// </summary>
        protected Endpoint GetStepDataIntraDayServiceEndpoint(DateTime day)
        {
            return new Endpoint
            {
                BaseUri = "https://api.fitbit.com",
                Resource = String.Format("/1/user/-/activities/steps/date/{0}/1d/1min.json", day.ToString("yyyy-MM-dd"))
            };
        }

        protected override void BeforeGetAccessToken(BeforeAfterRequestArgs args)
        {
            args.Client.Authenticator = new HttpBasicAuthenticator(Configuration.ClientId, Configuration.ClientSecret);
            base.BeforeGetAccessToken(args);
        }

        protected override void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
            args.Client.Authenticator = new OAuth2AuthorizationRequestHeaderAuthenticator(AccessToken, "Bearer");
            base.BeforeGetUserInfo(args);
        }

        /// <summary>
        /// Should return parsed <see cref="UserInfo"/> from content received from third-party service.
        /// </summary>
        /// <param name="content">The content which is received from third-party service.</param>
        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            var names = response["user"]["fullName"].Value<string>().Split(' ');
            var avatarUri = response["user"]["avatar"].Value<string>();
            return new UserInfo
            {
                Id = response["user"]["encodedId"].Value<string>(),
                FirstName = names.Any() ? names.First() : response["user"]["displayName"].Value<string>(),
                LastName = names.Count() > 1 ? names.Last() : string.Empty,
                AvatarUri =
                    {
                        Small = null,
                        Normal = avatarUri,
                        Large = null
                    }
            };
        }

        public string GetIntraDayStepData(DateTime day)
        {
            Action<BeforeAfterRequestArgs> hook = (args) => BeforeGetUserInfo(args);
            IRestResponse result = GetResponse(this.GetStepDataIntraDayServiceEndpoint(day), hook);
            return result.Content;
        }

        /// <summary>
        /// Friendly name of provider (OAuth2 service).
        /// </summary>
        public override string Name
        {
            get { return "Fitbit"; }
        }
    }
}