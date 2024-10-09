using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class Messages
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? id { get; set; }

        [BsonElement("conversation_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? conversation_id { get; set; }

        [BsonElement("sender_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? sender_id { get; set; } 

        [BsonElement("receiver_id")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? receiver_id { get; set; } 

        [BsonElement("voice_path")]
        public string? voice_path { get; set;}

        [BsonElement("timestamp")]
        public DateTime? timestamp { get; set; }
    }
}