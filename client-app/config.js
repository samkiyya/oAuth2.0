require('dotenv').config();

module.exports = {
  port: process.env.PORT || 3001,
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  authServerUrl: process.env.AUTH_SERVER_URL,
  resourceServerUrl: process.env.RESOURCE_SERVER_URL,
  redirectUri: process.env.REDIRECT_URI,
  scope: 'profile',
};
