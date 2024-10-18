using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class LoginAttempts
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? id { get; set; }

        [BsonElement("user_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? user_id { get; set; }

        [BsonElement("attempt_count")]
        public int? attempt_count { get; set; }

        [BsonElement("last_attempt_time")]
        public DateTime? last_attempt_time { get; set; }

        [BsonElement("is_blocked")]
        public bool? is_blocked { get; set; }
    }
}