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
            var existingUser = await _context.Find(u => u.Email == user.Email).FirstOrDefaultAsync();
            if (existingUser != null)
            {
                return BadRequest("Email is already registered.");
            }

            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            user.CreatedAt = DateTime.Now;

            await _context.InsertOneAsync(user);

            return Ok("User registered successfully.");
        }

        // LOGIN
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLogin login)
        {
            // Find user by email
            var existingUser = await _context.Find(u => u.Email == login.Email).FirstOrDefaultAsync();
            if (existingUser == null)
            {
                return Unauthorized("Invalid email or password.");
            }

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(login.Password, existingUser.Password))
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
            // ตรวจสอบค่าของ user
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            if (string.IsNullOrEmpty(user.Id))
            {
                throw new ArgumentException("User ID cannot be null or empty.", nameof(user.Id));
            }

            if (string.IsNullOrEmpty(user.Email))
            {
                throw new ArgumentException("User Email cannot be null or empty.", nameof(user.Email));
            }

            // สำหรับ Username ถ้า null ให้คืนค่าข้อความแสดงข้อผิดพลาด
            if (string.IsNullOrEmpty(user.Username))
            {
                throw new ArgumentException("User Username cannot be null or empty.", nameof(user.Username));
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
            new Claim(ClaimTypes.NameIdentifier, user.Id),
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
