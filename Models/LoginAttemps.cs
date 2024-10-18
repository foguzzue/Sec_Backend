using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class LoginAttemps
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? id { get; set; }

        [BsonElement("user_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? user_id { get; set; }
        
        [BsonElement("attemp_count")]
        public int? attemp_count { get; set; }

        [BsonElement("last_attemp_time")]
        public DateTime? last_attemp_time { get; set; }

        [BsonElement("is_blocked")]
        public bool? is_blocked { get; set; }
    }
}