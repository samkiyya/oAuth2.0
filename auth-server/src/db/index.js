import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import config from '../../config.js';

// Configure lowdb to write to JSONFile
const adapter = new JSONFile('db.json');
const db = new Low(adapter);

// Read data from JSON file, this will set db.data content
await db.read();

// If db.json is empty, initialize it with default data
db.data ||= { clients: [], authCodes: [], refreshTokens: [] };

// Set the clients from the config file.
// In a real application, you would have a UI or a CLI to manage clients.
db.data.clients = config.db.clients;

await db.write();

export default db;