import express, { Request, Response, NextFunction } from 'express';
import { EnokiFlow } from '@mysten/enoki';
import {
  SuiClient,
  getFullnodeUrl,
//   ,
//   type SerializedSignature,
} from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { ZkLoginSignatureInputs, getZkLoginSignature } from '@mysten/sui/zklogin';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import axios from 'axios';
import dotenv from 'dotenv';
import { type toSerializedSignature } from '@mysten/sui/cryptography';

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
const PORT = 3000;

// Configuration
const suiClient = new SuiClient({ url: getFullnodeUrl('mainnet') });
// const enokiClient = new EnokiClient({
//   apiKey: process.env.ENOKI_API_KEY || 'your-enoki-api-key',
// });
const enokiFlow = new EnokiFlow({apiKey: process.env.ENOKI_API_KEY! });
const JWT_SECRET = process.env.JWT_SECRET!;
const API_KEY = process.env.API_KEY;
const ZKLOGIN_PROVER_URL = 'https://prover-dev.mystenlabs.com/v1';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;

// Interfaces for request bodies and JWT payload
export interface JwtPayload {
  address: string;
}

interface MoveCallRequest {
  zkLoginSignature: string;
  address: string;
  packageId: string;
  module: string;
  func: string;
  args: string[];
}

interface AuthResponse {
  address: string;
  token: string;
  zkLoginSignature: string;
}

// Middleware
app.use(express.json());
app.use(helmet());
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://your-game-domain.com'],
    methods: ['GET', 'POST'],
  })
);
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, please try again later.',
  })
);

// JWT verification middleware
const verifyJwt = (req: Request, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// API key verification middleware
const verifyApiKey = (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== API_KEY) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  next();
};

// Validate zkLogin signature (placeholder)
const validateZkLoginSignature = async (
  signature: string,
  address: string,
  txb: Transaction
): Promise<boolean> => {
  try {
    // Placeholder: Implement verification with Sui SDK
    return true;
  } catch (error) {
    return false;
  }
};

// Google OAuth redirect
// app.get('/auth/google', async (req: Request, res: Response) => {
//   try {
//     const googleSignInUrl = await enokiFlow.createAuthorizationURL({
//       provider: 'google',
//       clientId: GOOGLE_CLIENT_ID,
//       redirectUrl: GOOGLE_REDIRECT_URI,
//       extraParams: {
//         scope: ['openid', 'email', 'profile'],
//     },
//     });
//     res.redirect(googleSignInUrl);
//   } catch (error) {
//     res.status(500).json({ error: `Failed to initiate OAuth: ${error}` });
//   }
// });

// Google OAuth redirect
app.get('/auth/google', (req: Request, res: Response) => {
  const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}&` +
    `redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&` +
    `response_type=code&` +
    `scope=openid%20email&` +
    `access_type=offline`;
  res.redirect(redirectUrl);
});

// OAuth callback
app.get('/auth/callback', async (req: Request, res: Response) => {
    console.log(req.query);
  const { code } = req.query as { code: string };
  try {
    console.log("ppppppppp");
    console.log(code);
    console.log(GOOGLE_CLIENT_ID);
    console.log(GOOGLE_CLIENT_SECRET);
    console.log(GOOGLE_REDIRECT_URI);

    // console.log(enokiFlow.getKeypair());
    // Exchange code for id_token
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code',
    });
    console.log("ooooooooo");
    const idToken = tokenResponse.data.id_token;
    console.log(idToken);
    console.log("qqqqqqqq");

    // Decode JWT to get address (using Enoki HTTP API or fallback)
    const decodedJwt = jwt.decode(idToken) as { sub?: string; iss?: string };
    if (!decodedJwt.sub || !decodedJwt.iss) {
      throw new Error('Invalid JWT: missing sub or iss');
    }
    console.log(decodedJwt);
    console.log("rrrrrrrr");
    // Fetch zkLogin proof from prover
    const proofResponse = await axios.post(ZKLOGIN_PROVER_URL, {
      jwt: idToken,
      salt: 'your-salt',
      maxEpoch: 10000,
      keyClaimName: 'sub',
    });
    const inputs: ZkLoginSignatureInputs = proofResponse.data;
    console.log("sssssssss");
    // Derive address (placeholder, as Enoki may provide this in future)
    const address = `0x${Buffer.from(decodedJwt.sub).toString('hex').slice(0, 64)}`; // Simplified; replace with Enoki address derivation when available
    console.log(address);
    // Construct zkLogin signature
    const signature = getZkLoginSignature({
      inputs,
      maxEpoch: 100,
      userSignature: 'mock-user-signature', // Replace with actual user signature
    });

    // Generate JWT for session
    const token = jwt.sign({ address }, JWT_SECRET, { expiresIn: '1h' });
    const response: AuthResponse = { address, token, zkLoginSignature: JSON.stringify(signature) };
    res.json(response);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Check balance
app.get(
  '/balance/:address',
  verifyJwt,
  verifyApiKey,
  async (req: Request, res: Response) => {
    const { address } = req.params;
    if (!req.user || req.user.address !== address) {
      return res.status(403).json({ error: 'Unauthorized address' });
    }

    try {
      const balance = await suiClient.getBalance({ owner: address });
      res.json({ balance: parseFloat(balance.totalBalance) / 1_000_000_000 });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Execute Move call
app.post(
  '/moveCall',
  verifyJwt,
  verifyApiKey,
  async (req: Request, res: Response) => {
    const { zkLoginSignature, address, packageId, module, func, args } =
      req.body as MoveCallRequest;

    if (!zkLoginSignature || !address || !packageId || !module || !func || !Array.isArray(args)) {
      return res.status(400).json({ error: 'Invalid request parameters' });
    }
    if (!req.user || req.user.address !== address) {
      return res.status(403).json({ error: 'Unauthorized address' });
    }
    if (args.some((arg) => !arg.match(/^0x[0-9a-fA-F]+$/))) {
      return res.status(400).json({ error: 'Invalid hex arguments' });
    }

    const txb = new Transaction();
    txb.moveCall({
      target: `${packageId}::${module}::${func}`,
      arguments: args.map((arg) => txb.pure.string(arg)),
    });
    txb.setGasBudget(10_000_000);

    const isValidSignature = await validateZkLoginSignature(zkLoginSignature, address, txb);
    if (!isValidSignature) {
      return res.status(403).json({ error: 'Invalid zkLogin signature' });
    }

    try {
      const result = await suiClient.executeTransactionBlock({
        transactionBlock: await txb.build({ client: suiClient }),
        signature: zkLoginSignature,
        requestType: 'WaitForLocalExecution',
        options: { showEffects: true },
      });
      res.json({ success: true, result });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});