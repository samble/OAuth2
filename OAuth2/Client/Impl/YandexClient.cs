using System.Linq;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp;
using System.Collections;

namespace OAuth2.Client.Impl
{
    /// <summary>
    /// Yandex authentication client.
    /// </summary>
    public class YandexClient : OAuth2Client
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="YandexClient"/> class.
        /// </summary>
        /// <param name="factory">The factory.</param>
        /// <param name="configuration">The configuration.</param>
        /// <param name="persistor">Object to store token info between instantiations (e.g. web requests - <see cref="SessionPersistor"/>)</param>
        public YandexClient(IRequestFactory factory, IClientConfiguration configuration, IDictionary persistor = null)
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
                    BaseUri = "https://oauth.yandex.ru",
                    Resource = "/authorize"
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
                    BaseUri = "https://oauth.yandex.ru",
                    Resource = "/token"
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
                    BaseUri = "https://login.yandex.ru",
                    Resource = "/info"
                };
            }
        }

        /// <summary>
        /// Called just before issuing request to third-party service when everything is ready.
        /// Allows to add extra parameters to request or do any other needed preparations.
        /// </summary>
        protected override void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
            // Source document 
            // http://api.yandex.com/oauth/doc/dg/yandex-oauth-dg.pdf
        }

        /// <summary>
        /// Should return parsed <see cref="UserInfo"/> from content received from third-party service.
        /// </summary>
        /// <param name="content">The content which is received from third-party service.</param>
        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            var names = response["real_name"].Value<string>().Split(' ');
            return new UserInfo
            {
                Id = response["id"].Value<string>(),
                FirstName = names.Any() ? names.First() : response["display_name"].Value<string>(),
                LastName = names.Count() > 1 ? names.Last() : string.Empty,
                Email = response["default_email"].SafeGet(x => x.Value<string>()),
            };
        }

        public override string Name
        {
            get { return "Yandex"; }
        }
    }
}