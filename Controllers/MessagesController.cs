using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.IO;
using System.Security.Cryptography;

using Sec_Backend.Models;
using Sec_Backend.Services;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;

namespace Sec_Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class MessagesController : ControllerBase
    {
        private readonly IMongoCollection<Messages> _context;
        private readonly IConfiguration _configuration;

        public MessagesController(MongoDbService mongoDbService, IConfiguration configuration)
        {
            _context = mongoDbService.Database.GetCollection<Messages>("messages");
            _configuration = configuration;
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

                    var encryptedAudioBytes = EncryptAudio(audioBytes);
                    if (encryptedAudioBytes == null)
                    {
                        return StatusCode(500, "Audio encryption failed.");
                    }

                    var fileName = Path.Combine("D:\\Work\\Y4.1\\Security\\voice", Guid.NewGuid().ToString() + Path.GetExtension(audioFile.FileName));
                    await System.IO.File.WriteAllBytesAsync(fileName, encryptedAudioBytes);

                    var hashFilePath = EncryptPath(fileName);

                    newMessage.voice_path = hashFilePath;
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }

            // อัปเดต timestamp
            newMessage.timestamp = DateTime.UtcNow.AddHours(7);
            await _context.InsertOneAsync(newMessage);

            // หลังจากสร้างข้อความแล้ว ให้แก้ไข lastest_timestamp ในการสนทนาที่เกี่ยวข้อง
            var updateDefinition = Builders<Messages>.Update.Set(m => m.timestamp, newMessage.timestamp);
            var filter = Builders<Messages>.Filter.Eq(m => m.conversation_id, newMessage.conversation_id);

            var updateResult = await _context.UpdateOneAsync(filter, updateDefinition);

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
            existingMessage.voice_path = updatedMessage.voice_path ?? existingMessage.voice_path;
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

        [HttpGet("get-audio")]
        public async Task<IActionResult> GetAudio(string voice_path)
        {
            string decryptedPath = DecryptPath(voice_path);

            string filePath = Path.Combine("path_to_encrypted_files_directory", $"{decryptedPath}");
            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("File not found." + filePath);
            }

            byte[] encryptedAudio = await System.IO.File.ReadAllBytesAsync(filePath);
            byte[] decryptedAudio = DecryptAudio(encryptedAudio);

            return File(decryptedAudio, "audio/m4a");
        }

        private string EncryptPath(string path)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["BlowfishSettings:Key"]);
#pragma warning restore CS8604 // Possible null reference argument.
            IBufferedCipher cipher = CipherUtilities.GetCipher("Blowfish/ECB/PKCS7");
            cipher.Init(true, new KeyParameter(key));

            byte[] inputBytes = Encoding.UTF8.GetBytes(path);
            byte[] outputBytes = cipher.DoFinal(inputBytes);

            return Convert.ToBase64String(outputBytes);
        }

        private string DecryptPath(string encryptedPath)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["BlowfishSettings:Key"]);
#pragma warning restore CS8604 // Possible null reference argument.
            IBufferedCipher cipher = CipherUtilities.GetCipher("Blowfish/ECB/PKCS7");
            cipher.Init(false, new KeyParameter(key));

            byte[] inputBytes = Convert.FromBase64String(encryptedPath);
            byte[] outputBytes = cipher.DoFinal(inputBytes);

            return Encoding.UTF8.GetString(outputBytes);
        }

        private byte[] EncryptAudio(byte[] audioBytes)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            var key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            var iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            csEncrypt.Write(audioBytes, 0, audioBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            return msEncrypt.ToArray();
                        }
                    }
                }
            }
        }

        private byte[] DecryptAudio(byte[] encryptedAudioBytes)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            byte[] key = Convert.FromBase64String(_configuration["EncryptionSettings:Key"]);
            byte[] iv = Convert.FromBase64String(_configuration["EncryptionSettings:IV"]);
#pragma warning restore CS8604 // Possible null reference argument.

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (var msDecrypt = new MemoryStream(encryptedAudioBytes))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var msResult = new MemoryStream())
                            {
                                csDecrypt.CopyTo(msResult);
                                return msResult.ToArray();
                            }
                        }
                    }
                }
            }
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

    }
}
