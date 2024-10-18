using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;

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
        private readonly CryptographySevice _cryptographySevice;

        public UsersController(MongoDbService mongoDbService, CryptographySevice cryptographySevice)
        {
            _context = mongoDbService.Database.GetCollection<Users>("users");
            _cryptographySevice = cryptographySevice;
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

            var (publicKey, privateKey) = _cryptographySevice.GenerateKeyPair();

            user.publicKey = publicKey;
            user.privateKey = privateKey;

            await _context.InsertOneAsync(user);

            return Ok("User registered successfully.");
        }

        // LOGIN
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLogin login)
        {
            var existingUser = await _context.Find(u => u.email == login.email).FirstOrDefaultAsync();
            if (existingUser == null)
            {
                return Unauthorized("Invalid email or password.");
            }

            if (!BCrypt.Net.BCrypt.Verify(login.password, existingUser.password))
            {
                return Unauthorized("Invalid email or password.");
            }

            // Generate JWT token with 48 hours expiration
            var token = _cryptographySevice.GenerateJwtToken(existingUser);

            return Ok(new { token, userId = existingUser.id });
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
