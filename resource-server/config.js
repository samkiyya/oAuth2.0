require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3002,
  authServerUrl: process.env.AUTH_SERVER_URL,
  audience: process.env.AUDIENCE,
};
