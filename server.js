
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Your encryption key (replace with the actual key)
const secretFromConfiguration = "6721F8BF054AE14B37B191B0CC1F7C250940B59B22D47DA21804002EEBC7396C";

// Middleware to handle URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));

app.post('/pp-hosted/secure/webhook', (req, res) => {
  try {
    // Extracting the necessary values from the headers and body
    const ivfromHttpHeader = req.headers['x-initialization-vector'];
    const authTagFromHttpHeader = req.headers['x-authentication-tag'];
    const httpBody = req.body.data;  // Assuming the encrypted data is in the 'data' field

    // Convert data to Buffers
    const key = new Buffer(secretFromConfiguration, "hex");
    const iv = new Buffer(ivfromHttpHeader, "hex");
    const authTag = new Buffer(authTagFromHttpHeader, "hex");
    const cipherText = new Buffer(httpBody, "hex");

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

