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
using Microsoft.AspNetCore.Authorization;

namespace Sec_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly IMongoCollection<Users> _context;
        private readonly IConfiguration _configuration;

        public UsersController(MongoDbService mongoDbService, IConfiguration configuration)
        {
            _context = mongoDbService.Database.GetCollection<Users>("users");
            _configuration = configuration;
        }

        // REGISTER
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] Users user)
        {
            var existingUser = await _context.Find(u => u.email == user.email).FirstOrDefaultAsync();
            if (existingUser != null)
            {
                return BadRequest("Email is already registered.");
            }

            user.password = BCrypt.Net.BCrypt.HashPassword(user.password);
            user.createdAt = DateTime.UtcNow.AddHours(7);

            await _context.InsertOneAsync(user);

            return Ok("User registered successfully.");
        }

        // LOGIN
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLogin login)
        {
            // Find user by email
            var existingUser = await _context.Find(u => u.email == login.email).FirstOrDefaultAsync();
            if (existingUser == null)
            {
                return Unauthorized("Invalid email or password.");
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(login.password, existingUser.password))
            {
                return Unauthorized("Invalid email or password.");
            }

            // Generate JWT token with 48 hours expiration
            var token = GenerateJwtToken(existingUser);

            return Ok(new { token, userId = existingUser.id });
        }

        // Generate JWT Token
        private string GenerateJwtToken(Users user)
        {
            // ตรวจสอบค่าของ user
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            if (string.IsNullOrEmpty(user.id))
            {
                throw new ArgumentException("User ID cannot be null or empty.", nameof(user.id));
            }

            if (string.IsNullOrEmpty(user.email))
            {
                throw new ArgumentException("User Email cannot be null or empty.", nameof(user.email));
            }

            // สำหรับ Username ถ้า null ให้คืนค่าข้อความแสดงข้อผิดพลาด
            if (string.IsNullOrEmpty(user.username))
            {
                throw new ArgumentException("User Username cannot be null or empty.", nameof(user.username));
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var secretKey = _configuration["Jwt:SecretKey"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("JWT SecretKey is not configured.");
            }

            var key = Encoding.ASCII.GetBytes(secretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.NameIdentifier, user.id),
            new Claim(ClaimTypes.Email, user.email),
            new Claim(ClaimTypes.Name, user.username)
        }),
                Expires = DateTime.UtcNow.AddHours(48), // Token valid for 48 hours
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _context.Find(new BsonDocument()).ToListAsync();

            var result = users.Select(user => new 
            {
                Id = user.id,
                Username = user.username 
            });

            return Ok(result);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("User ID is required.");
            }

            var result = await _context.DeleteOneAsync(u => u.id == id);
            if (result.DeletedCount == 0)
            {
                return NotFound("User not found.");
            }

            return Ok("User deleted successfully.");
        }

    }
}
