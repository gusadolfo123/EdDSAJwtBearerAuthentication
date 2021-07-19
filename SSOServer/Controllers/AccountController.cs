using EdDSAJwtBearer;
using Microsoft.AspNetCore.Mvc;
using SSOServer.Data;
using SSOServer.Models;
using SSOServer.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SSOServer.Controllers
{
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly EdDSAJwtBearerServer _server;

        public AccountController(EdDSAJwtBearerServer server)
        { 
            _server = server;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] UserCredentials credentials)
        {
            IActionResult response = Unauthorized();
            var user = Repository.GetUser(credentials.Email, credentials.Password);
            if (user != null)
            {
                string token = CreateToken(_server, user);
                response = Ok(token);

            }
            return response;
        }

        private string CreateToken(EdDSAJwtBearerServer server, User user)
        {
            var claims = new List<Claim>
            {
                new Claim("sub", user.Id.ToString()),
                new Claim("firstName", user.FirstName),
                new Claim("lastName", user.LastName),
                new Claim("email", user.Email) 
            };

            return server.CreateToken(claims, user.Roles, DateTime.Now.AddMinutes(30));
        }

    }
}
