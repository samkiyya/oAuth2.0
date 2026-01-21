require('dotenv').config();
const fs = require('fs');

module.exports = {
  port: process.env.PORT || 3000,
  issuer: process.env.ISSUER,
  privateKey: fs.readFileSync('private.key', 'utf8'),
  db: {
    clients: [
      {
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        redirect_uris: [process.env.REDIRECT_URI],
        scope: 'profile',
      },
    ],
  },
};
