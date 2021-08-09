using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Codenation.Challenge.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Source;
using Microsoft.AspNetCore.TestHost;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Codenation.Challenge.Controllers;

namespace Codenation.Challenge
{
    public class AuthenticationTest
    {
        private TestServer server;
        private TestServer authServer;

        public AuthenticationTest()
        {
            var authBuilder = new WebHostBuilder().
                UseEnvironment("Development").
                UseStartup<StartupIdentityServer>();
            authServer = new TestServer(authBuilder);            
            authServer.BaseAddress = new Uri("http://localhost:5000");

            var builder = new WebHostBuilder().
                UseEnvironment("Testing").
                ConfigureServices(services => {
                    services.Configure<JwtBearerOptions>( "Bearer", jwtOpts => {
                        jwtOpts.BackchannelHttpHandler = authServer.CreateHandler();
                    });
                }).
                UseStartup<Startup>();

            server = new TestServer(builder);            
            server.BaseAddress = new Uri("http://localhost:5000");
        }       

        private Dictionary<string, string> GetTokenParameters(string email, string password)
        {
            var parameters = new Dictionary<string, string>();
            parameters["client_id"] = "codenation.api_client";
            parameters["client_secret"] = "codenation.api_secret";
            parameters["grant_type"] = "password";
            parameters["scope"] = "codenation";
            parameters["username"] = email;
            parameters["password"] = password;
            return parameters;
        }

        private Token GetToken(string email, string password)
        {
            var parameters = GetTokenParameters(email, password);
            var client = authServer.CreateClient();
            HttpResponseMessage response = client.PostAsync("/connect/token", 
                new FormUrlEncodedContent(parameters)).Result;
            response.EnsureSuccessStatusCode();
            return response.Content.ReadAsAsync<Token>().Result;
        }

        [Theory]
        [InlineData("UserController")]
        [InlineData("CompanyController")]
        [InlineData("AccelerationController")]
        [InlineData("CandidateController")]
        [InlineData("SubmissionController")]
        public void Should_Has_Authorize_Attribute_On_Controller(string controller)
        {
            var attributes = Type.GetType($"Codenation.Challenge.Controllers.{controller}, Source").
                GetCustomAttributes(false).Select(x => x.GetType().Name).ToList();
            Assert.Contains("AuthorizeAttribute", attributes);
        }

        [Theory]
        [InlineData("/api/user")]
        [InlineData("/api/company")]
        [InlineData("/api/acceleration")]
        [InlineData("/api/candidate")]
        [InlineData("/api/submission")]
        public void Should_Route_Be_Not_Authorized_When_Call_With_No_Token(string endpoint)
        {
            var client = server.CreateClient();
            var actual = client.GetAsync(endpoint).Result;            
            Assert.Equal(HttpStatusCode.Unauthorized, actual.StatusCode);
        }

        [Fact]
        public void Should_Challenge_Route_Be_Authorized_When_Call_With_No_Token()
        {
            var client = server.CreateClient();
            var actual = client.GetAsync("/api/challenge").Result;            
            Assert.NotEqual(HttpStatusCode.Unauthorized, actual.StatusCode);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(10)]
        public void Should_Be_Generate_A_Valid_Token(int userId)
        {
            var fakes = new Fakes();
            var user = fakes.Get<UserDTO>().Find(x => x.Id == userId);

            var client = authServer.CreateClient();
            var actual = GetToken(user.Email, user.Password);

            Assert.NotNull(actual);
            Assert.NotEmpty(actual.access_token);
            Assert.True(actual.expires_in > 0);
            Assert.Equal("Bearer", actual.token_type);
            Assert.Equal("codenation", actual.scope);
        }

        [Theory]
        [InlineData(1, "/api/company")]
        [InlineData(3, "/api/acceleration")]
        [InlineData(5, "/api/candidate")]
        [InlineData(7, "/api/submission")]
        public void Should_User_Be_Authorized_On_Endpoint_With_Token(int userId, string endpoint)
        {
            var fakes = new Fakes();
            var user = fakes.Get<UserDTO>().Find(x => x.Id == userId);

            var token = GetToken(user.Email, user.Password);
            Assert.NotNull(token);

            var client = server.CreateClient();
            client.SetBearerToken(token.access_token);            
            var actual = client.GetAsync(endpoint).Result;
            Assert.NotEqual(HttpStatusCode.Unauthorized, actual.StatusCode);
            Assert.NotEqual(HttpStatusCode.Forbidden, actual.StatusCode);
        }

        [Fact]
        public void Should_Admin_Be_Authorized_On_Route_User()
        {
            var fakes = new Fakes();
            var user = fakes.Get<UserDTO>().Find(x => x.Id == 10);

            var token = GetToken(user.Email, user.Password);
            Assert.NotNull(token);

            var client = server.CreateClient();
            client.SetBearerToken(token.access_token);            

            var actual = client.GetAsync("/api/user/1").Result;
            Assert.NotEqual(HttpStatusCode.Unauthorized, actual.StatusCode);
            Assert.NotEqual(HttpStatusCode.Forbidden, actual.StatusCode);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(7)]
        [InlineData(9)]
        public void Should_Non_Admin_User_Be_Not_Authorized_On_Route_User(int userId)
        {
            var fakes = new Fakes();
            var user = fakes.Get<UserDTO>().Find(x => x.Id == userId);

            var token = GetToken(user.Email, user.Password);
            Assert.NotNull(token);

            var client = server.CreateClient();
            client.SetBearerToken(token.access_token);            

            var actual = client.GetAsync("/api/user/1").Result;
            Assert.Equal(HttpStatusCode.Forbidden, actual.StatusCode);
        }

    }
}

