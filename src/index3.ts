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


// using UnityEngine;
// using UnityEngine.Networking;
// using System.Collections;

// public class SuiZkLoginMoveCall : MonoBehaviour
// {
//   private static string myServer = "http://localhost:3000";
//   private string balanceUrl = myServer+"/balance/";
//   private string moveCallUrl = myServer+"/moveCall";
//   private string userAddress;
//   private string jwtToken;
//   private string apiKey = "your-api-key";
//   private string zkLoginSignature; // Set after zkLogin (JSON string)

//   public void StartZkLogin()
//   {
//     // Open OAuth login in a WebView (e.g., UniWebView)
//     Application.OpenURL(myServer+"/auth/google");
//     // After redirect, handle callback (simplified)
//     StartCoroutine(CheckAuthCallback());
//   }

//   private IEnumerator CheckAuthCallback()
//   {
//     using (UnityWebRequest www = UnityWebRequest.Get(myServer+"/auth/callback"))
//     {
//       yield return www.SendWebRequest();
//       Debug.Log(www.result);
//       Debug.Log(UnityWebRequest.Result.Success);
//       if (www.result == UnityWebRequest.Result.Success)
//       {
//         var response = JsonUtility.FromJson<AuthResponse>(www.downloadHandler.text);
//         userAddress = response.address;
//         jwtToken = response.token;
//         // Assume zkLoginSignature is obtained via WebView or server
//         zkLoginSignature = response.zkLoginSignature; // Update server to return this
//         Debug.Log("Authenticated: " + userAddress);
//       }
//       else
//       {
//         Debug.LogError("Auth Error: " + www.error);
//       }
//     }
//   }

//   public void CheckBalanceAndMintNFT()
//   {
//     StartCoroutine(CheckBalance());
//   }

//   private IEnumerator CheckBalance()
//   {
//     using (UnityWebRequest www = UnityWebRequest.Get(balanceUrl + userAddress))
//     {
//       www.SetRequestHeader("Authorization", "Bearer " + jwtToken);
//       www.SetRequestHeader("x-api-key", apiKey);
//       yield return www.SendWebRequest();
//       if (www.result == UnityWebRequest.Result.Success)
//       {
//         float balance = float.Parse(www.downloadHandler.text);
//         if (balance >= 0.01f)
//         {
//           StartCoroutine(MintNFT());
//         }
//         else
//         {
//           Debug.Log("Please fund your address: " + userAddress);
//         }
//       }
//       else
//       {
//         Debug.LogError("Balance Error: " + www.error);
//       }
//     }
//   }

//   private IEnumerator MintNFT()
//   {
//     string jsonPayload = JsonUtility.ToJson(new MoveCallData
//     {
//       zkLoginSignature = zkLoginSignature,
//       address = userAddress,
//       packageId = "0xYourContractAddress",
//       module = "nft",
//       func = "mint_nft",
//       args = new string[] { "0x4e4654" }
//     });

//     using (UnityWebRequest www = UnityWebRequest.Post(moveCallUrl, jsonPayload, "application/json"))
//     {
//       www.SetRequestHeader("Authorization", "Bearer " + jwtToken);
//       www.SetRequestHeader("x-api-key", apiKey);
//       yield return www.SendWebRequest();
//       if (www.result == UnityWebRequest.Result.Success)
//       {
//         Debug.Log("NFT Minted: " + www.downloadHandler.text);
//       }
//       else
//       {
//         Debug.LogError("Mint Error: " + www.error);
//       }
//     }
//   }

//   [System.Serializable]
//   private struct MoveCallData
//   {
//     public string zkLoginSignature;
//     public string address;
//     public string packageId;
//     public string module;
//     public string func;
//     public string[] args;
//   }

//   [System.Serializable]
//   private struct AuthResponse
//   {
//     public string address;
//     public string token;
//     public string zkLoginSignature; // Add if server returns it
//   }
// }

























// using UnityEngine;
// using UnityEngine.Networking;
// using System.Collections;
// using Newtonsoft.Json;

// public class SuiZkLoginMoveCall : MonoBehaviour
// {
//     private static string myServer = "http://localhost:3000";
//     private string balanceUrl = myServer + "/balance/";
//     private string moveCallUrl = myServer + "/moveCall";
//     private string userAddress;
//     private string jwtToken;
//     private string apiKey = "your-api-key"; // Replace with actual key or load from config
//     private string sessionId;

//     [System.Serializable]
//     private struct AuthResponse
//     {
//         public string authUrl;
//         public string sessionId;
//         public string jwt;
//         public string address;
//         public string error;
//     }

//     [System.Serializable]
//     private struct BalanceResponse
//     {
//         public float balance;
//         public string error;
//     }

//     [System.Serializable]
//     private struct MoveCallData
//     {
//         public string address;
//         public string packageId;
//         public string module;
//         public string func;
//         public string[] args;
//     }

//     [System.Serializable]
//     private struct MoveCallResponse
//     {
//         public string result;
//         public string error;
//     }

//     public void StartZkLogin()
//     {
//         StartCoroutine(StartAuth());
//     }

//     private IEnumerator StartAuth()
//     {
//         using (UnityWebRequest www = UnityWebRequest.Get(myServer + "/auth/google"))
//         {
//             yield return www.SendWebRequest();

//             if (www.result == UnityWebRequest.Result.Success)
//             {
//                 var response = JsonConvert.DeserializeObject<AuthResponse>(www.downloadHandler.text);
//                 sessionId = response.sessionId;
//                 Debug.Log($"Starting auth with sessionId: {sessionId}");
//                 Application.OpenURL(response.authUrl);
//                 yield return new WaitForSeconds(5); // Wait for user to start login
//                 StartCoroutine(PollForSession());
//             }
//             else
//             {
//                 Debug.LogError($"Auth start failed: {www.error}, Status: {www.responseCode}, Response: {www.downloadHandler.text}");
//             }
//         }
//     }

//     private IEnumerator PollForSession()
//     {
//         int attempts = 0;
//         const int maxAttempts = 30; // 60 seconds

//         while (string.IsNullOrEmpty(jwtToken) && attempts < maxAttempts)
//         {
//             attempts++;
//             yield return new WaitForSeconds(2);
//             using (UnityWebRequest www = UnityWebRequest.Get(myServer + "/auth/session/" + sessionId))
//             {
//                 yield return www.SendWebRequest();

//                 Debug.Log($"Poll result: {www.result}, Error: {www.error}, Status: {www.responseCode}, Response: {www.downloadHandler.text}");

//                 if (www.result == UnityWebRequest.Result.Success)
//                 {
//                     var response = JsonConvert.DeserializeObject<AuthResponse>(www.downloadHandler.text);
//                     if (string.IsNullOrEmpty(response.error))
//                     {
//                         jwtToken = response.jwt;
//                         userAddress = response.address;
//                         Debug.Log($"Authenticated: {userAddress}");
//                         yield break;
//                     }
//                     else
//                     {
//                         Debug.Log($"Session error: {response.error}");
//                     }
//                 }
//                 else
//                 {
//                     Debug.LogError($"Poll failed: {www.error}, Status: {www.responseCode}, Response: {www.downloadHandler.text}");
//                 }
//             }
//         }

//         if (string.IsNullOrEmpty(jwtToken))
//         {
//             Debug.LogError("Authentication timed out");
//         }
//     }

//     public void CheckBalanceAndMintNFT()
//     {
//         if (string.IsNullOrEmpty(userAddress))
//         {
//             Debug.LogError("User not authenticated");
//             return;
//         }
//         StartCoroutine(CheckBalance());
//     }

//     private IEnumerator CheckBalance()
//     {
//         using (UnityWebRequest www = UnityWebRequest.Get(balanceUrl + userAddress))
//         {
//             www.SetRequestHeader("Authorization", "Bearer " + jwtToken);
//             www.SetRequestHeader("x-api-key", apiKey);
//             yield return www.SendWebRequest();

//             if (www.result == UnityWebRequest.Result.Success)
//             {
//                 var response = JsonConvert.DeserializeObject<BalanceResponse>(www.downloadHandler.text);
//                 if (string.IsNullOrEmpty(response.error))
//                 {
//                     float balance = response.balance;
//                     Debug.Log($"Balance: {balance} SUI");
//                     if (balance >= 0.01f)
//                     {
//                         StartCoroutine(MintNFT());
//                     }
//                     else
//                     {
//                         Debug.Log($"Insufficient balance: {userAddress} has {balance} SUI");
//                     }
//                 }
//                 else
//                 {
//                     Debug.LogError($"Balance error: {response.error}");
//                 }
//             }
//             else
//             {
//                 Debug.LogError($"Balance failed: {www.error}, Status: {www.responseCode}, Response: {www.downloadHandler.text}");
//             }
//         }
//     }

//     private IEnumerator MintNFT()
//     {
//         var payload = new MoveCallData
//         {
//             address = userAddress,
//             packageId = "0xYourContractAddress", // Replace with actual contract address
//             module = "nft",
//             func = "mint_nft",
//             args = new string[] { "Sword" } // Adjust based on Move function
//         };

//         string jsonPayload = JsonConvert.SerializeObject(payload);
//         using (UnityWebRequest www = UnityWebRequest.Post(moveCallUrl, jsonPayload, "application/json"))
//         {
//             www.SetRequestHeader("Authorization", "Bearer " + jwtToken);
//             www.SetRequestHeader("x-api-key", apiKey);
//             yield return www.SendWebRequest();

//             if (www.result == UnityWebRequest.Result.Success)
//             {
//                 var response = JsonConvert.DeserializeObject<MoveCallResponse>(www.downloadHandler.text);
//                 if (string.IsNullOrEmpty(response.error))
//                 {
//                     Debug.Log($"NFT Minted: {response.result}");
//                 }
//                 else
//                 {
//                     Debug.LogError($"Mint error: {response.error}");
//                 }
//             }
//             else
//             {
//                 Debug.LogError($"Mint failed: {www.error}, Status: {www.responseCode}, Response: {www.downloadHandler.text}");
//             }
//         }
//     }
// }
