using MongoDB.Driver;

namespace Sec_Backend.Services
{
    public class MongoDbService
    {
        private readonly IConfiguration _configuration;
        private readonly IMongoDatabase _database;

        public MongoDbService(IConfiguration configuration){
            _configuration = configuration;

            var connectionString = _configuration.GetConnectionString("DbConnection");
            var databaseName = _configuration.GetConnectionString("DatabaseName");
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase(databaseName);
        }

        public IMongoDatabase Database => _database;
    }
}