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
    public class MessagesController : ControllerBase
    {
        private readonly IMongoCollection<Messages> _context;
        private readonly IConfiguration _configuration;
        private readonly CryptographySevice _cryptographySevice;

        public MessagesController(MongoDbService mongoDbService, IConfiguration configuration, CryptographySevice cryptographySevice)
        {
            _context = mongoDbService.Database.GetCollection<Messages>("messages");
            _configuration = configuration;
            _cryptographySevice = cryptographySevice;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Messages>>> GetAllMessages()
        {
            var messages = await _context.Find(new BsonDocument()).ToListAsync();
            return Ok(messages);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetMessageById(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Message ID is required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Message ID format.");
            }

            var message = await _context.Find(m => m.id == id).FirstOrDefaultAsync();

            if (message == null)
            {
                return NotFound("Message not found.");
            }

            return Ok(message);
        }

        [HttpGet("get-all-by-conversation-id/{conversationId}")]
        public async Task<IActionResult> GetAllMessagesByConversationId(string conversationId)
        {
            if (string.IsNullOrEmpty(conversationId))
            {
                return BadRequest("Conversation ID is required.");
            }

            if (!ObjectId.TryParse(conversationId, out _))
            {
                return BadRequest("Invalid Conversation ID format.");
            }

            var messages = await _context.Find(m => m.conversation_id == conversationId).ToListAsync();

            return Ok(messages);
        }

        [HttpGet("get-audio")]
        public async Task<IActionResult> GetAudio(string voice_path)
        {
            string decryptedPath = _cryptographySevice.DecryptPathBlowfish(voice_path);
            string filePath = Path.Combine("path_to_encrypted_files_directory", $"{decryptedPath}");

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("File not found." + filePath);
            }

            byte[] encryptedAudio = await System.IO.File.ReadAllBytesAsync(filePath);
            byte[] decryptedAudio = _cryptographySevice.DecryptAudioAES(encryptedAudio);

            var message = await _context.Find(m => m.voice_path == voice_path).FirstOrDefaultAsync();

#pragma warning disable CS8604 // Possible null reference argument.
            if (message == null)
            {
                return BadRequest("Message not found.");
            }

            // **ตรวจสอบ Digital Signature**
            var signatureBytes = Convert.FromBase64String(message.digital_sig);
            if (!_cryptographySevice.VerifySignature(decryptedAudio, signatureBytes, message.sender_id))
            {
                return BadRequest("Digital signature verification failed.");
            }
#pragma warning restore CS8604 // Possible null reference argument.
            // var fileName = Path.Combine("D:\\Work\\Y4.1\\Security\\voice\\de", "test.m4a");
            // await System.IO.File.WriteAllBytesAsync(fileName, decryptedAudio);

            return File(decryptedAudio, "audio/m4a");
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateMessage([FromForm] Messages newMessage, IFormFile audioFile)
        {
            if (newMessage == null)
            {
                return BadRequest("Message data is required.");
            }

            if (audioFile == null || audioFile.Length == 0)
            {
                return BadRequest("Audio file is required.");
            }

            if (string.IsNullOrEmpty(newMessage.conversation_id) ||
                string.IsNullOrEmpty(newMessage.sender_id) ||
                string.IsNullOrEmpty(newMessage.receiver_id))
            {
                return BadRequest("All fields are required.");
            }

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    await audioFile.CopyToAsync(memoryStream);
                    var audioBytes = memoryStream.ToArray();

                    var encryptedAudioBytes = _cryptographySevice.EncryptAudioAES(audioBytes);
                    if (encryptedAudioBytes == null)
                    {
                        return StatusCode(500, "Audio encryption failed.");
                    }

                    var fileName = Path.Combine("D:\\Work\\Y4.1\\Security\\voice", Guid.NewGuid().ToString() + Path.GetExtension(audioFile.FileName));
                    await System.IO.File.WriteAllBytesAsync(fileName, encryptedAudioBytes);

                    var hashFilePath = _cryptographySevice.EncryptPathBlowfish(fileName);
                    newMessage.voice_path = hashFilePath;

                    // **สร้าง Digital Signature**
                    var digitalSignature = _cryptographySevice.SignData(audioBytes, newMessage.sender_id);
                    newMessage.digital_sig = Convert.ToBase64String(digitalSignature);  // เก็บลายเซ็นในฐานข้อมูล
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }

            newMessage.timestamp = DateTime.UtcNow.AddHours(7);
            await _context.InsertOneAsync(newMessage);

            var _conversation = _context.Database.GetCollection<Conversation>("conversation");
            var conversation = await _conversation.Find(x => x.id == newMessage.conversation_id).FirstOrDefaultAsync();

            conversation.lastest_timestamp = newMessage.timestamp.Value;

            await _conversation.ReplaceOneAsync(x => x.id == newMessage.conversation_id, conversation);

            return CreatedAtAction(nameof(GetMessageById), new { id = newMessage.id }, newMessage);
        }


        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateMessage(string id, [FromBody] Messages updatedMessage)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Message ID is required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Message ID format.");
            }

            var existingMessage = await _context.Find(m => m.id == id).FirstOrDefaultAsync();

            if (existingMessage == null)
            {
                return NotFound("Message not found.");
            }

            existingMessage.conversation_id = updatedMessage.conversation_id ?? existingMessage.conversation_id;
            existingMessage.sender_id = updatedMessage.sender_id ?? existingMessage.sender_id;
            existingMessage.receiver_id = updatedMessage.receiver_id ?? existingMessage.receiver_id;
            existingMessage.timestamp = DateTime.UtcNow.AddHours(7);

            await _context.ReplaceOneAsync(m => m.id == id, existingMessage);

            return Ok(existingMessage);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteMessage(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest("Message ID is required.");
            }

            if (!ObjectId.TryParse(id, out _))
            {
                return BadRequest("Invalid Message ID format.");
            }

            var deleteResult = await _context.DeleteOneAsync(m => m.id == id);

            if (deleteResult.DeletedCount == 0)
            {
                return NotFound("Message not found.");
            }

            return NoContent();
        }
    }
}
