using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class Users
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? id { get; set; }

        [BsonElement("email")]
        public string? email { get; set; }

        [BsonElement("password")]
        public string? password { get; set; }

        [BsonElement("username")]
        public string? username { get; set; }
        [BsonElement("private_key")]
        public string? privateKey { get; set; }

        [BsonElement("public_key")]
        public string? publicKey { get; set; }

        [BsonElement("createdAt")]
        public DateTime createdAt { get; set; }
    }

    public class UserLogin
    {
        [BsonElement("email")]
        public string email { get; set; } = null!; // Required email field

        [BsonElement("password")]
        public string password { get; set; } = null!; // Required password field
    }
}
