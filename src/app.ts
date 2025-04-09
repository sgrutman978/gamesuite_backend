import express from 'express';
import { ed25519 } from '@noble/curves/ed25519';
import cors from 'cors';
import bodyParser from 'body-parser';
import { randomBytes } from 'crypto';

const app = express();

// Private key for signing (keep this secure!)
const PRIVATE_KEY = Buffer.from('your-32-byte-private-key-hex', 'hex'); // Replace with a real key
const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY); // 32-byte public key
const ALLOWED_ORIGIN = 'http://localhost';

async function generateEd25519KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const privateKey = randomBytes(32); // Generate a 32-byte random private key
    const publicKey = await ed25519.getPublicKey(privateKey); // Derive the public key from the private key
    return { publicKey, privateKey };
  }

// Middleware to check origin
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || origin === ALLOWED_ORIGIN) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));

// app.use(express.json());
app.use(bodyParser.json());

app.post('/submit-score', (req: any, res: any) => {
    const { playerAddress, score } = req.body;
});

app.post('/submit-score', (req: any, res: any) => {
    const { playerAddress, score } = req.body;

    if (!playerAddress || !score || score < 0) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    // Create message to sign (e.g., playerAddress + score)
    const message = `${playerAddress}${score}`;
    const messageHash = Buffer.from(message).toString('hex');

    // Sign the message
    const signature = ed25519.sign(messageHash, PRIVATE_KEY);

    res.json({
        playerAddress,
        score,
        signature: Buffer.from(signature).toString('hex'), // 64-byte signature
        publicKey: Buffer.from(PUBLIC_KEY).toString('hex') // 32-byte public key
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
