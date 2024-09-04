const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Your encryption key (replace with the actual key)
const secretFromConfiguration = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

// Middleware to handle URL-encoded bodies
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.raw({ type: 'text/plain', limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/pp-hosted/secure/webhook', (req, res) => {
  try {
 
    // Extracting the necessary values from the headers and body

    const ivfromHttpHeader = req.headers['x-initialization-vector'];
    const authTagFromHttpHeader = req.headers['x-authentication-tag'];
    const httpBody = req.body.encryptedBody;   

    // Log the extracted values to ensure they are correct

    console.log('IV:', ivfromHttpHeader);
    console.log('Auth Tag:', authTagFromHttpHeader);
    console.log('Encrypted Data:', httpBody);

    // Ensure none of the values are undefined

    if (!ivfromHttpHeader || !authTagFromHttpHeader || !httpBody) {
      throw new Error('Missing required decryption parameters');
    }

    // Convert data to Buffers

    const key = Buffer.from(secretFromConfiguration, "hex");
    const iv = Buffer.from(ivfromHttpHeader, "hex");
    const authTag = Buffer.from(authTagFromHttpHeader, "hex");
    const cipherText = Buffer.from(httpBody, "hex");

    // Prepare decryption
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    // Decrypt
    const result = decipher.update(cipherText, 'hex', 'utf8') + decipher.final('utf8');
    console.log('Decrypted result:', result);

    // Respond with a 200 status code
    res.status(200).send('Webhook received and decrypted successfully.');
  } catch (error) {
    console.error('Failed to decrypt webhook:', error.message);
    res.status(500).send('Internal Server Error');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
