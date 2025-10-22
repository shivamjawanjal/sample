from pymongo.mongo_client import MongoClient #type: ignore
from pymongo.server_api import ServerApi #type: ignore
uri = "mongodb+srv://shivamjpatil2007:changeMe@cluster0.6hbppqx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
# Create a new client and connect to the server
client = MongoClient(uri)
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
    def get_database():
        db = client['Khatabook']
        return db
except Exception as e:
    print(e)