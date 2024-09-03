const express = require('express');
const bodyParser = require('body-parser');
const winston = require('winston');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;
const encryptionKey = Buffer.from('6721F8BF054AE14B37B191B0CC1F7C250940B59B22D47DA21804002EEBC7396C', 'hex'); // Replace with your actual encryption key

// Middleware to parse both JSON bodies and raw bodies
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.raw({ type: 'text/plain', limit: '100kb' }));

// Simple logging setup using winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

function decrypt(encryptedData, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Route to handle POST requests to /pp-hosted/secure/webhook
app.post('/pp-hosted/secure/webhook', (req, res) => {
  try {
    logger.info('Webhook received.');

    // Check if the webhook is encrypted by looking for the encryption headers
    const iv = req.headers['x-initialization-vector'];
    const authTag = req.headers['x-authentication-tag'];

    let webhookPayload;

    if (iv && authTag) {
      logger.info('Processing encrypted webhook.');

      const encryptedData = req.body.toString('hex'); // Convert raw buffer to hex string

      // Decrypt the data
      const decryptedData = decrypt(encryptedData, iv, authTag);
      logger.info('Decrypted data:', decryptedData);

      // Parse the decrypted data as JSON
      webhookPayload = JSON.parse(decryptedData);
    } else {
      logger.info('Processing unencrypted webhook.');

      // Process the unencrypted JSON payload directly
      webhookPayload = req.body;
    }

    // Log the webhook payload for both encrypted and unencrypted
    logger.info('Webhook Payload:', webhookPayload);

    // Respond with a 200 status code
    res.status(200).send('Webhook received successfully.');
  } catch (error) {
    logger.error('Failed to process webhook:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Start the server
const server = app.listen(port, () => {
  logger.info(`Server is listening on port ${port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT signal received: closing HTTP server');
  server.close(() => {
    logger.info('HTTP server closed');
  });
});
