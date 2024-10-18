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
        private readonly IMongoCollection<LoginAttempts> _loginAttempts;

        public UsersController(MongoDbService mongoDbService, CryptographySevice cryptographySevice)
        {
            _context = mongoDbService.Database.GetCollection<Users>("users");
            _cryptographySevice = cryptographySevice;
            _loginAttempts = mongoDbService.Database.GetCollection<LoginAttempts>("login_attempts");
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

            var loginAttempt = new LoginAttempts { user_id = user.id, attempt_count = 0 };
            await _loginAttempts.InsertOneAsync(loginAttempt);

            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLogin login)
        {
            var existingUser = await _context.Find(u => u.email == login.email).FirstOrDefaultAsync();

            if (existingUser == null)
            {
                return NotFound("This email does not exist");
            }

            var loginAttempt = await _loginAttempts.Find(x => x.user_id == existingUser.id).FirstOrDefaultAsync();

            // ตรวจสอบว่า user ถูกบล็อคหรือไม่
            if (loginAttempt?.is_blocked == true)
            {
                if (loginAttempt.last_attempt_time.HasValue &&
                    DateTime.UtcNow.AddHours(7) < loginAttempt.last_attempt_time.Value.AddMinutes(30))
                {
                    var remainingTime = loginAttempt.last_attempt_time.Value.AddMinutes(30) - DateTime.UtcNow.AddHours(7);
                    return Conflict(new
                    {
                        message = "Account is blocked. Please try again later.",
                        remainingTime = (int)remainingTime.TotalMinutes
                    });
                }

                // Reset the attempt count after 30 minutes
                loginAttempt.attempt_count = 0;
                loginAttempt.is_blocked = false;
                await _loginAttempts.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
            }

            // ตรวจสอบรหัสผ่าน
            if (!BCrypt.Net.BCrypt.Verify(login.password, existingUser.password))
            {
                loginAttempt ??= new LoginAttempts { user_id = existingUser.id, attempt_count = 0 }; // Initialize if null
                loginAttempt.attempt_count++;
                loginAttempt.last_attempt_time = DateTime.UtcNow.AddHours(7);

#pragma warning disable CS8629 // Nullable value type may be null.
                int remainingAttempts = Math.Max(0, 5 - (int)loginAttempt.attempt_count); // คำนวณจำนวนครั้งที่เหลือ
#pragma warning restore CS8629 // Nullable value type may be null.

                if (loginAttempt.attempt_count >= 5)
                {
                    loginAttempt.is_blocked = true;
                    await _loginAttempts.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
                    var remainingTime = loginAttempt.last_attempt_time.Value.AddMinutes(30) - DateTime.UtcNow.AddHours(7);
                    return Conflict(new
                    {
                        message = "Account is blocked. Please try again later.",
                        remainingTime = (int)remainingTime.TotalMinutes
                    });
                }

                await _loginAttempts.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
                return Unauthorized(new { message = "Invalid email or password.", remainingAttempts });
            }

            // Successful login
            if (loginAttempt != null)
            {
                // Reset attempt count
                loginAttempt.attempt_count = 0;
                loginAttempt.is_blocked = false;
                await _loginAttempts.ReplaceOneAsync(x => x.user_id == existingUser.id, loginAttempt);
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
