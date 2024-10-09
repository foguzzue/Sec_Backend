using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authorization;


using Sec_Backend.Models;
using Sec_Backend.Services;

namespace Sec_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ConversationController : ControllerBase
    {
        private readonly IMongoCollection<Conversation> _context;

        public ConversationController(MongoDbService mongoDbService)
        {
            _context = mongoDbService.Database.GetCollection<Conversation>("conversation");
        }

        [HttpGet]
        public async Task<IEnumerable<Conversation>> GetAllConversation()
        {
            return await _context.Find(new BsonDocument()).ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetConversationById(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Conversation ID is required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Conversation ID format.");
            }

            var conversation = await _context.Find(c => c.id == id).FirstOrDefaultAsync();

            if (conversation == null)
            {
                return NotFound("Conversation not found.");
            }

            return Ok(conversation);
        }

        [HttpGet("user/{userId}")]
        public async Task<IActionResult> GetConversationsByUser(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("User ID is required.");
            }

            var filter = Builders<Conversation>.Filter.Or(
                Builders<Conversation>.Filter.Eq(c => c.user_1, userId),
                Builders<Conversation>.Filter.Eq(c => c.user_2, userId)
            );

            var conversations = await _context.Find(filter).ToListAsync();

            if (conversations == null || conversations.Count == 0)
            {
                return NotFound("No conversations found for the user.");
            }

            var results = new List<dynamic>();
            foreach (var conversation in conversations)
            {
#pragma warning disable CS8604 // Possible null reference argument.
                var user1 = await GetUserById(conversation.user_1);
                var user2 = await GetUserById(conversation.user_2);
#pragma warning restore CS8604 // Possible null reference argument.

                results.Add(new
                {
                    conversationId = conversation.id,
                    user_1 = new { id = conversation.user_1, user1.username },
                    user_2 = new { id = conversation.user_2, user2.username },
                    conversation.lastest_timestamp
                });
            }

            var sortedResults = results.OrderByDescending(r => r.latest_timestamp).ToList(); 

            return Ok(sortedResults);
        }


        private async Task<Users> GetUserById(string userId)
        {
            var userCollection = _context.Database.GetCollection<Users>("users");
            return await userCollection.Find(u => u.id == userId).FirstOrDefaultAsync();
        }


        [HttpPost("create")]
        public async Task<IActionResult> CreateConversation([FromQuery] string user_1, [FromQuery] string user_2)
        {
            if (string.IsNullOrEmpty(user_1) || string.IsNullOrEmpty(user_2))
            {
                return BadRequest("User_1 and User_2 IDs are required.");
            }

            var existingConversation = await _context.Find(c => (c.user_1 == user_1 && c.user_2 == user_2) || (c.user_1 == user_2 && c.user_2 == user_1)).FirstOrDefaultAsync();
            if (existingConversation != null)
            {
                return BadRequest("Conversation already exists between these users.");
            }

            var newConversation = new Conversation
            {
                user_1 = user_1,
                user_2 = user_2,
                lastest_timestamp = DateTime.UtcNow.AddHours(7)
            };

            await _context.InsertOneAsync(newConversation);

            return Ok(new { message = "Conversation created successfully", conversationId = newConversation.id });
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateConversation(string id, [FromBody] Conversation updatedConversation)
        {
            if (string.IsNullOrEmpty(id) || updatedConversation == null)
            {
                return BadRequest("Conversation ID and updated data are required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Conversation ID format.");
            }

            var existingConversation = await _context.Find(c => c.id == id).FirstOrDefaultAsync();
            if (existingConversation == null)
            {
                return NotFound("Conversation not found.");
            }

            existingConversation.user_1 = updatedConversation.user_1;
            existingConversation.user_2 = updatedConversation.user_2;

            await _context.ReplaceOneAsync(c => c.id == id, existingConversation);

            return Ok("Conversation updated successfully.");
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteConversation(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Conversation ID is required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Conversation ID format.");
            }

            var result = await _context.DeleteOneAsync(c => c.id == id);
            if (result.DeletedCount == 0)
            {
                return NotFound("Conversation not found.");
            }

            return Ok("Conversation deleted successfully.");
        }

    }
}