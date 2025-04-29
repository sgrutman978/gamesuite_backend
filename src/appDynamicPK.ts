import express from 'express';
import { ed25519 } from '@noble/curves/ed25519';
import cors from 'cors';
import bodyParser from 'body-parser';
import { randomBytes } from 'crypto';
// import NodeRSA from 'encrypt-rsa';

const app = express();

// Private key for signing (keep this secure!)
// const nodeRSA = new NodeRSA();
// const { publicKey, privateKey } = nodeRSA.createPrivateAndPublicKeys();
// console.log('Public Key:', publicKey);
// console.log('Private Key:', privateKey);
const PRIVATE_KEY = Buffer.from("297cc73016130fab46c66a81816ea4bf8fe497c30d9b56f9c5d30ebb541b81db", 'hex'); // Replace with a real key
// const PUBLIC_KEY = ed25519.getPublicKey(PRIVATE_KEY); // 32-byte public key
const ALLOWED_ORIGIN = 'http://localhost';

// let keyMap = new Map<string, Buffer<ArrayBufferLike>>();

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

// app.post('/new-leaderboard-keypair', (req: any, res: any) => {
//     // const { k, i, o, m } = req.body;
//     generateEd25519KeyPair().then((data) => {
//         // let encPriv = nodeRSA.encrypt({
//         //     text: Buffer.from(data.privateKey).toString('hex')
//         // });
//         res.json({
//             wink: data.privateKey,
//             p: data.publicKey
//         });
//     });
// });

app.post('/submit-score', (req: any, res: any) => {
    const { a, s, p, w } = req.body;
    let playerAddress = a;
    let score = s;
    // let public_key = p;
    // let wink = Buffer.from(nodeRSA.decrypt({
    //     text: w
    // }));

    if (!playerAddress || !score || score < 0) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    // Create message to sign (e.g., playerAddress + score)
    const message = `${playerAddress}${score}`;
    const messageHash = Buffer.from(message).toString('hex');

    // Sign the message
    const signature = ed25519.sign(messageHash, PRIVATE_KEY); //wink

    res.json({
        // addy: playerAddress,
        // score: score,
        s: Buffer.from(signature).toString('hex'), // 64-byte signature
        // publicKey: Buffer.from(PUBLIC_KEY).toString('hex') // 32-byte public key
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
