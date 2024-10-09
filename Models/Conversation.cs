using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class Conversation
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? id { get; set; }

        [BsonElement("user_1")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? user_1 { get; set; }

        [BsonElement("user_2")]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? user_2 { get; set; }

        [BsonElement("lastest_timestamp")]
        public DateTime lastest_timestamp { get; set; }
    }
}