import app from './src/app.js';
import config from './config.js';

app.listen(config.port, () => {
    console.log(`Authorization server running on http://localhost:${config.port}`);
});
