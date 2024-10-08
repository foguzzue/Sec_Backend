using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using System.Threading.Tasks;
using BCrypt.Net;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using Sec_Backend.Models;
using Sec_Backend.Services;
using MongoDB.Bson;
using Microsoft.Extensions.Configuration; // Add this

namespace Sec_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IMongoCollection<Users> _context;
        private readonly IConfiguration _configuration; // Add this

        // Modify constructor to inject IConfiguration
        public UsersController(MongoDbService mongoDbService, IConfiguration configuration)
        {
            _context = mongoDbService.Database.GetCollection<Users>("users");
            _configuration = configuration; // Set the _configuration
        }

        // REGISTER
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Users user)
        {
            // Check if the email already exists
            var existingUser = await _context.Find(u => u.Email == user.Email).FirstOrDefaultAsync();
            if (existingUser != null)
            {
                return BadRequest("Email is already registered.");
            }

            // Hash the password
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.CreatedAt = DateTime.Now;

            await _context.InsertOneAsync(user);

            return Ok("User registered successfully.");
        }

        // LOGIN
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Users user)
        {
            // Find user by email
            var existingUser = await _context.Find(u => u.Email == user.Email).FirstOrDefaultAsync();
            if (existingUser == null)
            {
                return Unauthorized("Invalid email or password.");
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, existingUser.Password))
            {
                return Unauthorized("Invalid email or password.");
            }

            // Generate JWT token with 48 hours expiration
            var token = GenerateJwtToken(existingUser);

            return Ok(new { token });
        }

        // Generate JWT Token
        private string GenerateJwtToken(Users user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.Username)
                }),
                Expires = DateTime.UtcNow.AddHours(48), // Token valid for 48 hours
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        [HttpGet]
        public async Task<IEnumerable<Users>> GetAllUsers()
        {
            return await _context.Find(new BsonDocument()).ToListAsync();
        }
    }
}
