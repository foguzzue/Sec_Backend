using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Sec_Backend.Models
{
    public class Users
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string? Id { get; set; }

        [BsonElement("email")]
        public string? Email { get; set; }

        [BsonElement("password")]
        public string? Password { get; set; }

        [BsonElement("username")]
        public string? Username { get; set; }

        [BsonElement("createdAt")]
        public DateTime CreatedAt { get; set; }
    }

    public class UserLogin
    {
        [BsonElement("email")]
        public string Email { get; set; } = null!; // Required email field

        [BsonElement("password")]
        public string Password { get; set; } = null!; // Required password field
    }
}
