import app from './src/app.js';
import config from './config.js';

app.listen(config.port, () => {
    console.log(`Resource Server running on port ${config.port}`);
});
