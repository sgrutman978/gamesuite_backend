// import express, { Request, Response, NextFunction } from 'express';
// import {
//   SuiClient,
//   getFullnodeUrl,
// } from '@mysten/sui.js/client';
// import { TransactionBlock } from '@mysten/sui.js/transactions';
// import { ZkLoginSignatureInputs, getZkLoginSignature,
//   computeZkLoginAddressFromSeed } from '@mysten/sui.js/zklogin';
// import jwt from 'jsonwebtoken';
// import cors from 'cors';
// import rateLimit from 'express-rate-limit';
// import helmet from 'helmet';
// import axios from 'axios';
// import dotenv from 'dotenv';
// import { blake2b } from '@noble/hashes/blake2b';
// import { type SerializedSignature } from '@mysten/sui.js/cryptography';

// // Load environment variables
// dotenv.config();

// // Initialize Express
// const app = express();
// const PORT = 3000;

// // Configuration
// const client = new SuiClient({ url: getFullnodeUrl('devnet') });
// const JWT_SECRET = process.env.JWT_SECRET;
// const API_KEY = process.env.API_KEY;
// const ZKLOGIN_PROVER_URL = 'https://prover-dev.mystenlabs.com/v1';
// const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
// const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
// const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

// // Interfaces for request bodies and JWT payload
// export interface JwtPayload {
//   address: string;
// }

// interface MoveCallRequest {
//   zkLoginSignature: SerializedSignature;
//   address: string;
//   packageId: string;
//   module: string;
//   func: string;
//   args: string[];
// }

// interface AuthResponse {
//   address: string;
//   token: string;
//   zkLoginSignature: string;
// }

// // Middleware
// app.use(express.json());
// app.use(helmet());
// app.use(
//   cors({
//     origin: ['http://localhost:3000', 'https://your-game-domain.com'],
//     methods: ['GET', 'POST'],
//   })
// );
// app.use(
//   rateLimit({
//     windowMs: 15 * 60 * 1000,
//     max: 100,
//     message: 'Too many requests, please try again later.',
//   })
// );

// // JWT verification middleware
// const verifyJwt = (req: Request, res: Response, next: NextFunction) => {
//   const token = req.headers.authorization?.split(' ')[1];
//   if (!token) {
//     return res.status(401).json({ error: 'No token provided' });
//   }

//   try {
//     const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
//     req.user = decoded;
//     next();
//   } catch (error) {
//     res.status(401).json({ error: 'Invalid token' });
//   }
// };

// // API key verification middleware
// const verifyApiKey = (req: Request, res: Response, next: NextFunction) => {
//   const apiKey = req.headers['x-api-key'];
//   if (apiKey !== API_KEY) {
//     return res.status(403).json({ error: 'Invalid API key' });
//   }
//   next();
// };

// // Validate zkLogin signature
// const validateZkLoginSignature = async (
//   signature: SerializedSignature,
//   address: string,
//   txb: TransactionBlock
// ): Promise<boolean> => {
//   try {
//     // Placeholder: Implement verification with Sui SDK
//     return true;
//   } catch (error) {
//     return false;
//   }
// };

// // Google OAuth redirect
// app.get('/auth/google', (req: Request, res: Response) => {
//   const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
//     `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}&` +
//     `redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&` +
//     `response_type=code&` +
//     `scope=openid%20email&` +
//     `access_type=offline`;
//   res.redirect(redirectUrl);
// });

// // OAuth callback
// app.get('/auth/callback', async (req: Request, res: Response) => {
//   const { code } = req.query as { code: string };
//   console.log("meheheheheheh");
//   console.log(code);
//   try {
//     const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
//       code,
//       client_id: GOOGLE_CLIENT_ID,
//       client_secret: GOOGLE_CLIENT_SECRET,
//       redirect_uri: GOOGLE_REDIRECT_URI,
//       grant_type: 'authorization_code',
//     });
//     const idToken = tokenResponse.data.id_token;
//     console.log(idToken);

//     const zkLoginData = await generateZkLoginSignature(idToken, 'your-salt', 100);
//     const { address, signature } = zkLoginData;

//     const token = jwt.sign({ address }, JWT_SECRET, { expiresIn: '1h' });
//     const response: AuthResponse = { address, token, zkLoginSignature: JSON.stringify(signature) };
//     res.json(response);
//   } catch (error: any) {
//     res.status(500).json({ error: error.message });
//   }
// });

// // Check balance
// app.get(
//   '/balance/:address',
//   verifyJwt,
//   verifyApiKey,
//   async (req: Request, res: Response) => {
//     const { address } = req.params;
//     if (!req.user || req.user.address !== address) {
//       return res.status(403).json({ error: 'Unauthorized address' });
//     }

//     try {
//       const balance = await client.getBalance({ owner: address });
//       res.json({ balance: parseFloat(balance.totalBalance) / 1_000_000_000 });
//     } catch (error: any) {
//       res.status(500).json({ error: error.message });
//     }
//   }
// );

// // Execute Move call
// app.post(
//   '/moveCall',
//   verifyJwt,
//   verifyApiKey,
//   async (req: Request, res: Response) => {
//     const { zkLoginSignature, address, packageId, module, func, args } =
//       req.body as MoveCallRequest;

//     if (!zkLoginSignature || !address || !packageId || !module || !func || !Array.isArray(args)) {
//       return res.status(400).json({ error: 'Invalid request parameters' });
//     }
//     if (!req.user || req.user.address !== address) {
//       return res.status(403).json({ error: 'Unauthorized address' });
//     }
//     if (args.some((arg) => !arg.match(/^0x[0-9a-fA-F]+$/))) {
//       return res.status(400).json({ error: 'Invalid hex arguments' });
//     }

//     const txb = new TransactionBlock();
//     txb.moveCall({
//       target: `${packageId}::${module}::${func}`,
//       arguments: args.map((arg) => txb.pure(arg)),
//     });
//     txb.setGasBudget(10_000_000);

//     const isValidSignature = await validateZkLoginSignature(zkLoginSignature, address, txb);
//     if (!isValidSignature) {
//       return res.status(403).json({ error: 'Invalid zkLogin signature' });
//     }

//     try {
//       const result = await client.executeTransactionBlock({
//         transactionBlock: await txb.build({ client }),
//         signature: zkLoginSignature,
//         requestType: 'WaitForLocalExecution',
//         options: { showEffects: true },
//       });
//       res.json({ success: true, result });
//     } catch (error: any) {
//       res.status(500).json({ error: error.message });
//     }
//   }
// );

// // Start server
// app.listen(PORT, () => {
//   console.log(`Server running on port ${PORT}`);
// });

// // Generate zkLogin signature
// async function generateZkLoginSignature(
//   idToken: string,
//   salt: string,
//   maxEpoch: number
// ): Promise<{
//   address: string;
//   signature: SerializedSignature;
// }> {
//   try {
//     console.log("ppppppppp");
//     // Decode JWT to extract sub and iss
//     const decodedJwt = jwt.decode(idToken) as { sub?: string; iss?: string };
//     if (!decodedJwt.sub || !decodedJwt.iss) {
//       throw new Error('Invalid JWT: missing sub or iss');
//     }

//     console.log("qqqqqqq");
//     // Compute seed for address derivation
//     const seedInput = `${decodedJwt.sub}:${decodedJwt.iss}:${salt}`;
//     const seedBytes = blake2b(seedInput, { dkLen: 32 });
//     const seedBigInt = BigInt(`0x${Buffer.from(seedBytes).toString('hex')}`);

//     // Derive Sui address
//     const address = computeZkLoginAddressFromSeed(seedBigInt, decodedJwt.iss);
//   console.log("rrrrrrr");
//     // Fetch zkLogin proof from prover
//     const proofResponse = await axios.post(ZKLOGIN_PROVER_URL, {
//       jwt: idToken,
//       salt,
//       maxEpoch,
//       keyClaimName: 'sub',
//     });
//     console.log("sssssss");
//     const inputs: ZkLoginSignatureInputs = proofResponse.data;

//     // Construct zkLogin signature
//     const signature = getZkLoginSignature({
//       inputs,
//       maxEpoch,
//       userSignature: 'mock-user-signature', // Replace with actual user signature
//     });
//     console.log("tttttt");

//     return { address, signature };
//   } catch (error) {
//     throw new Error(`Failed to generate zkLogin signature: ${error}`);
//   }
// }