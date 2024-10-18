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
        private readonly IMongoCollection<LoginAttemps> _loginAttemps;

        public UsersController(MongoDbService mongoDbService, CryptographySevice cryptographySevice)
        {
            _context = mongoDbService.Database.GetCollection<Users>("users");
            _cryptographySevice = cryptographySevice;
            _loginAttemps = mongoDbService.Database.GetCollection<LoginAttemps>("login_attemps");
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

            var loginAttempt = new LoginAttemps { user_id = user.id, attemp_count = 0 };
            await _loginAttemps.InsertOneAsync(loginAttempt);

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
                return NotFound("Invalid email or password.");
            }

            var loginAttempt = await _loginAttemps.Find(x => x.user_id == existingUser.id).FirstOrDefaultAsync();

            // Check if user is blocked
            if (loginAttempt != null && loginAttempt.is_blocked == true)
            {
                if (loginAttempt.last_attemp_time.HasValue && DateTime.UtcNow.AddHours(7) < loginAttempt.last_attemp_time.Value.AddMinutes(30))
                {
                    return Conflict("Account is blocked. Please try again later.");
                }
                else
                {
                    // Reset the attempt count after 30 minutes
                    loginAttempt.attemp_count = 0;
                    loginAttempt.is_blocked = false;
                    await _loginAttemps.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
                }
            }

            if (loginAttempt != null)
            {
                // Validate password
                if (!BCrypt.Net.BCrypt.Verify(login.password, existingUser.password))
                {
                    loginAttempt.attemp_count++;
                    loginAttempt.last_attemp_time = DateTime.UtcNow.AddHours(7);

#pragma warning disable CS8629 // Nullable value type may be null.
                    int remainingAttempts = (int)(10 - loginAttempt.attemp_count);
#pragma warning restore CS8629 // Nullable value type may be null.

                    if (loginAttempt.attemp_count >= 10)
                    {
                        loginAttempt.is_blocked = true;
                        return Conflict("Account is blocked. Please try again later.");
                    }

                    await _loginAttemps.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);

                    // คืนค่าจำนวนครั้งที่เหลือ
                    return Unauthorized(new { message = "Invalid email or password.", remainingAttempts });
                }

                // Successful login
                else
                {
                    // Reset attempt count
                    loginAttempt.attemp_count = 0;
                    loginAttempt.is_blocked = false;
                    await _loginAttemps.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
                }

            }
            else
            {
                return NotFound("Invalid email or password.");
            }

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
