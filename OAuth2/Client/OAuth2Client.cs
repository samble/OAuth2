using System;
using System.Collections.Specialized;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp;
using RestSharp.Authenticators;
using RestSharp.Extensions.MonoHttp;
using System.Web;
using System.Collections;

namespace OAuth2.Client
{
    /// <summary>
    /// Base class for OAuth2 client implementation.
    /// </summary>
    public abstract class OAuth2Client : IClient
    {
        private const string AccessTokenKey = "access_token";
        private const string RefreshTokenKey = "refresh_token";
        private const string ExpiresAtKey = "expires_in";
        private const string TokenTypeKey = "token_type";

        private const int ExpiresBufferMilliseconds = 10000;
        protected virtual int DefaultExpiresInSeconds
        {
            // https://tools.ietf.org/html/rfc6749#section-4.2.2
            // Server doesn't have to return expires_in
            // Default to one day
            get { return 3600 * 24; }
        }

        private readonly IRequestFactory _factory;

        private readonly IDictionary _persistor;

        /// <summary>
        /// Client configuration object.
        /// </summary>
        public IClientConfiguration Configuration { get; private set; }

        /// <summary>
        /// Friendly name of provider (OAuth2 service).
        /// </summary>
        public abstract string Name { get; }

        /// <summary>
        /// State (any additional information that was provided by application and is posted back by service).
        /// </summary>
        public string State { get; private set; }

        private string _accessToken;
        /// <summary>
        /// Access token returned by provider. Can be used for further calls of provider API.
        /// </summary>
        public string AccessToken
        {
            get
            {
                if (_accessToken == null && _persistor != null)
                    _accessToken = _persistor[PersistorKey(AccessTokenKey)] as string;
                return _accessToken;
            }

            private set
            {
                _accessToken = value;
                if (_persistor != null)
                {
                    _persistor[PersistorKey(AccessTokenKey)] = value;
                }
            }
        }

        private string _refreshToken;
        /// <summary>
        /// Refresh token returned by provider. Can be used for further calls of provider API.
        /// </summary>
        public string RefreshToken
        {
            get
            {
                if (_refreshToken == null && _persistor != null)
                    _refreshToken = _persistor[PersistorKey(RefreshTokenKey)] as string;
                return _refreshToken;
            }
            private set
            {
                _refreshToken = value;
                if (_persistor != null)
                {
                    _persistor[PersistorKey(RefreshTokenKey)] = value;
                }
            }
        }

        private string _tokenType;
        /// <summary>
        /// Token type returned by provider. Can be used for further calls of provider API.
        /// </summary>
        public string TokenType
        {
            get
            {
                if (_tokenType == null && _persistor != null)
                    _tokenType = _persistor[PersistorKey(TokenTypeKey)] as string;
                return _tokenType;
            }
            private set
            {
                _tokenType = value;
                if (_persistor != null)
                {
                    _persistor[PersistorKey(TokenTypeKey)] = value;
                }
            }
        }

        private DateTime? _expiresAt;
        /// <summary>
        /// Seconds till the token expires returned by provider. Can be used for further calls of provider API.
        /// </summary>
        public DateTime ExpiresAt
        {
            get
            {
                if (!_expiresAt.HasValue && _persistor != null)
                    _expiresAt = _persistor[ExpiresAtKey] as DateTime?;
                return _expiresAt ?? DateTime.MaxValue;
            }
            private set
            {
                _expiresAt = value;
                if (_persistor != null)
                {
                    _persistor[PersistorKey(ExpiresAtKey)] = value;
                }
            }
        }

        private string GrantType { get; set; }

        protected OAuth2Client(IRequestFactory factory, IClientConfiguration configuration) : this(factory, configuration, null) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2Client"/> class.
        /// </summary>
        /// <param name="factory">The factory.</param>
        /// <param name="configuration">The configuration.</param>
        /// <param name="persistor">Used to store key/values between requests (e.g. tokens).</param>
        protected OAuth2Client(IRequestFactory factory, IClientConfiguration configuration, IDictionary persistor)
        {
            _factory = factory;
            Configuration = configuration;
            _persistor = persistor;
        }

        /// <summary>
        /// True if you can make an API call, false if you need to redirect to GetLoginLinkUri() first
        /// </summary>
        /// <returns></returns>
        public bool IsLoggedIn
        {
            get { return IsCurrentAccessTokenValid || IsAccessTokenExpiredAndRefreshable; }
        }

        /// <summary>
        /// Returns true if AccessToken is present and unexpired
        /// </summary>
        private bool IsCurrentAccessTokenValid
        {
            get
            {
                return !String.IsNullOrEmpty(AccessToken) &&
                  ExpiresAt > DateTime.Now.AddMilliseconds(ExpiresBufferMilliseconds);
            }
        }

        /// <summary>
        /// Returns true if AccessToken expiration is in the past, and we have a refresh token
        /// </summary>
        /// <returns></returns>
        private bool IsAccessTokenExpiredAndRefreshable
        {
            get
            {
                return ExpiresAt < DateTime.Now.AddMilliseconds(ExpiresBufferMilliseconds)
                  && !String.IsNullOrEmpty(RefreshToken);
            }
        }

        /// <summary>
        /// Returns URI of service which should be called in order to start authentication process.
        /// This URI should be used for rendering login link.
        /// </summary>
        /// <param name="state">
        /// Any additional information that will be posted back by service.
        /// </param>
        public virtual string GetLoginLinkUri(string state = null)
        {
            var client = _factory.CreateClient(AccessCodeServiceEndpoint);
            var request = _factory.CreateRequest(AccessCodeServiceEndpoint);


            request.AddObject(new
            {
                response_type = "code",
                client_id = Configuration.ClientId,
                redirect_uri = Configuration.RedirectUri,
                state
            });

            if (!String.IsNullOrEmpty(Configuration.Scope))
            {
                request.AddParameter("scope", Configuration.Scope);
            }

            return client.BuildUri(request).ToString();
        }

        /// <summary>
        /// Obtains user information using OAuth2 service and data provided via callback request.
        /// </summary>
        /// <param name="parameters">Callback request payload (parameters).</param>
        public UserInfo GetUserInfo(NameValueCollection parameters)
        {
            FetchTokenFromLoginLinkUriRedirect(parameters);
            return GetUserInfo();
        }

        /// <summary>
        /// Obtains user information using provider API.
        /// </summary>
        public virtual UserInfo GetUserInfo()
        {
            Action<BeforeAfterRequestArgs> hook = (args) => BeforeGetUserInfo(args);

            IRestResponse response = GetAPIResponse(UserInfoServiceEndpoint, hook);

            var result = ParseUserInfo(response.Content);
            result.ProviderName = Name;

            return result;
        }

        /// <summary>
        /// Issues query for access token and returns access token.
        /// </summary>
        /// <param name="parameters">Callback request payload (parameters).</param>
        [Obsolete("Please use FetchTokenFromLoginLinkUriRedirect instead")]
        public string GetToken(NameValueCollection parameters)
        {
            FetchTokenFromLoginLinkUriRedirect(parameters);
            return AccessToken;
        }

        /// <summary>
        /// Handles redirect back from from GetLoginLinkUri()
        /// </summary>
        /// <param name="parameters">Callback request payload (parameters).</param>
        /// <returns>The fetched AccessToken</returns>
        public string FetchTokenFromLoginLinkUriRedirect(NameValueCollection requestParameters)
        {
            CheckErrorAndSetState(requestParameters);

            var client = _factory.CreateClient(AccessTokenServiceEndpoint);
            var request = _factory.CreateRequest(AccessTokenServiceEndpoint, Method.POST);

            BeforeGetAccessToken(new BeforeAfterRequestArgs
            {
                Client = client,
                Request = request,
                Parameters = requestParameters,
                Configuration = Configuration
            });

            var response = client.ExecuteAndVerify(request);

            string content = response.Content;

            AfterGetAccessToken(new BeforeAfterRequestArgs
            {
                Response = response
            });

            RefreshToken = ParseTokenResponse(content, RefreshTokenKey);

            return HandleTokenResponse(content);
        }

        /// <summary>
        /// Refreshes current AccessToken (and ExpiresAt)
        /// </summary>
        private void GetRefreshedAccessToken()
        {
            var client = _factory.CreateClient(AccessTokenServiceEndpoint);
            var request = _factory.CreateRequest(AccessTokenServiceEndpoint, Method.POST);

            BeforeGetRefreshAccessToken(new BeforeAfterRequestArgs
            {
                Client = client,
                Configuration = Configuration,
                Request = request
            });

            var response = client.ExecuteAndVerify(request);

            AfterGetAccessToken(new BeforeAfterRequestArgs
            {
                Response = response,
            });

            HandleTokenResponse(response.Content);
        }

        private string HandleTokenResponse(string responseContent)
        {
            AccessToken = ParseTokenResponse(responseContent, AccessTokenKey);

            if (String.IsNullOrEmpty(AccessToken))
                throw new UnexpectedResponseException(AccessTokenKey);

            TokenType = ParseTokenResponse(responseContent, TokenTypeKey);

            int expiresIn;
            if (Int32.TryParse(ParseTokenResponse(responseContent, ExpiresAtKey), out expiresIn) && expiresIn > 0)
            {
                ExpiresAt = DateTime.Now.AddSeconds(expiresIn);
            }
            else
            {
                ExpiresAt = DateTime.Now.AddSeconds(DefaultExpiresInSeconds);
            }

            return AccessToken;
        }

        /// <summary>
        /// Defines URI of service which issues access code.
        /// </summary>
        protected abstract Endpoint AccessCodeServiceEndpoint { get; }

        /// <summary>
        /// Defines URI of service which issues access token.
        /// </summary>
        protected abstract Endpoint AccessTokenServiceEndpoint { get; }

        /// <summary>
        /// Defines URI of service which allows to obtain information about user 
        /// who is currently logged in.
        /// </summary>
        protected abstract Endpoint UserInfoServiceEndpoint { get; }

        private void CheckErrorAndSetState(NameValueCollection parameters)
        {
            const string errorFieldName = "error";
            var error = parameters[errorFieldName];
            if (!error.IsEmpty())
            {
                throw new UnexpectedResponseException(errorFieldName);
            }

            State = parameters["state"];
        }

        protected virtual string ParseTokenResponse(string content, string key)
        {
            if (String.IsNullOrEmpty(content) || String.IsNullOrEmpty(key))
                return null;

            try
            {
                // response can be sent in JSON format
                var token = JObject.Parse(content).SelectToken(key);
                return token != null ? token.ToString() : null;
            }
            catch (JsonReaderException)
            {
                // or it can be in "query string" format (param1=val1&param2=val2)
                var collection = RestSharp.Extensions.MonoHttp.HttpUtility.ParseQueryString(content);
                return collection[key];
            }
        }

        /// <summary>
        /// Should return parsed <see cref="UserInfo"/> using content received from provider.
        /// </summary>
        /// <param name="content">The content which is received from provider.</param>
        protected abstract UserInfo ParseUserInfo(string content);

        protected virtual void BeforeGetAccessToken(BeforeAfterRequestArgs args)
        {
            args.Request.AddObject(new
            {
                code = args.Parameters.GetOrThrowUnexpectedResponse("code"),
                client_id = Configuration.ClientId,
                client_secret = Configuration.ClientSecret,
                redirect_uri = Configuration.RedirectUri,
                grant_type = "authorization_code"
            });
        }

        protected virtual void BeforeGetRefreshAccessToken(BeforeAfterRequestArgs args)
        {
            args.Request.AddObject(new
            {
                refresh_token = args.Parameters.GetOrThrowUnexpectedResponse(RefreshTokenKey),
                client_id = Configuration.ClientId,
                client_secret = Configuration.ClientSecret,
                grant_type = RefreshTokenKey
            });
        }

        /// <summary>
        /// Called just after obtaining response with access token from service.
        /// Allows to read extra data returned along with access token.
        /// Also called after refreshing token (no separate callback)
        /// </summary>
        protected virtual void AfterGetAccessToken(BeforeAfterRequestArgs args)
        {
        }

        /// <summary>
        /// Called just before issuing request to service when everything is ready.
        /// Allows to add extra parameters to request or do any other needed preparations.
        /// </summary>
        protected virtual void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
        }

        /// <summary>
        /// Performs a validated request to an API endpoint with callback hooks.
        /// Be sure to handle redirecting to GetLoginLinkUri() and before calling this.
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="beforeRequestHook"></param>
        /// <param name="afterRequestHook"></param>
        /// <returns></returns>
        protected virtual IRestResponse GetAPIResponse(Endpoint endpoint,
            Action<BeforeAfterRequestArgs> beforeRequestHook = null,
            Action<BeforeAfterRequestArgs> afterRequestHook = null)
        {
            if (!IsLoggedIn)
            {
                throw new InvalidOperationException("Must handle login flow before making API calls");
            }
            else if (!IsCurrentAccessTokenValid && IsAccessTokenExpiredAndRefreshable)
            {
                GetRefreshedAccessToken();
            }

            var client = _factory.CreateClient(endpoint);
            client.Authenticator = new OAuth2UriQueryParameterAuthenticator(AccessToken);
            var request = _factory.CreateRequest(endpoint);

            if (beforeRequestHook != null)
            {
                beforeRequestHook(new BeforeAfterRequestArgs
                {
                    Client = client,
                    Request = request,
                    Configuration = Configuration
                });
            }

            IRestResponse response = client.ExecuteAndVerify(request);

            if (afterRequestHook != null)
            {
                afterRequestHook(new BeforeAfterRequestArgs
                {
                    Response = response
                });
            }
            return response;
        }

        private string PersistorKey(string key)
        {
            return String.Format("{0}|+|{1}", Name, key);
        }
    }
}