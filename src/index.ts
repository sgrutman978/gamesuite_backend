import express from 'express';
import { EnokiClient, EnokiFlow } from '@mysten/enoki';
import { SuiClient } from '@mysten/sui.js/client';
import { decodeJwt } from 'jose';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Enoki and Sui clients
const enokiClient = new EnokiClient({
  apiKey: process.env.ENOKI_API_KEY || '',
});
const suiClient = new SuiClient({ url: 'https://fullnode.testnet.sui.io' });

// Store user sessions (in-memory for simplicity; use a database in production)
const userSessions: { [jwt: string]: { address: string; walletId: string } } = {};

// Start Enoki zkLogin flow
app.get('/auth/google', async (req, res) => {
  try {
    // const flow = await enokiClient startFlow({
    //   clientId: process.env.GOOGLE_CLIENT_ID || '',
    //   redirectUrl: 'http://localhost:3000/api/auth/callback',
    //   providers: ['google'],
    // });
    const flow = new EnokiFlow({apiKey: "enoki_public_10094b0bafc9ba2626fcbc02a1812d6b"});
   const redirectUri = "http://localhost:3000/auth/callback";
   const provider = "google";
   const clientId = "1010386909639-p3bjjhp05pnk5vhsqak41lausgtk75nf.apps.googleusercontent.com";
        // flow.createAuthorizationURL({
        //     provider: provider,
        //     network: 'mainnet',
        //     clientId: clientId,
        //     redirectUrl,
        //     extraParams: {
        //         scope: ['openid', 'email', 'profile'],
        //         response_type: "code",
        //     },
        // }).then((url) => {
        //     console.log(url);
        //     res.redirect(url);
        //     // window.location.href = url;
        //     // res.json({ authUrl: url });
        // }).catch((error) => {
        //     console.error(error);
        // });
        // app.get('/auth/google', (req: Request, res: Response) => {
          const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
            `client_id=${encodeURIComponent(clientId)}&` +
            `redirect_uri=${encodeURIComponent(redirectUri)}&` +
            `response_type=code&` +
            `scope=openid%20email&` +
            `access_type=offline`;
          res.redirect(redirectUrl);
        // });
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to start auth flow' });
  }
});

// Handle Enoki callback
app.get('/auth/callback', async (req, res) => {
  try {
    console.log("response of query");
    console.log(req.query);
    const { code, state } = req.query;
    console.log(code);
    const flow = new EnokiFlow({apiKey: "enoki_public_10094b0bafc9ba2626fcbc02a1812d6b"});
    console.log(flow);
    // let jwt = "";
    console.log("pppppp");
    // await flow.handleAuthCallback().then((jwtt) => {
    //     console.log("jwtt: "+jwtt);
    //     jwt = jwtt!;
    // }).catch((e) => {
    //     console.log(e);
    // });

    const jwt = await exchangeCodeForJwt(code as string, state as string);
    const decoded = decodeJwt(jwt);
    console.log(decoded);
    // const address = await enokiClient.getZkLoginAddress({ jwt });

    // Create or retrieve Invisible Wallet
    // const wallet = await enokiClient.createInvisibleWallet({ jwt });
    // userSessions[state as string] = { jwt, address, walletId: wallet.id };

    console.log("lllllll");
    // const decoded = decodeJwt(jwt);
    let address = "";
    await enokiClient.getZkLogin({ jwt }).then((resp) => {
        address = resp.address;
    });
    console.log(address);
    // Create or retrieve Invisible Wallet
    const wallet = flow.$zkLoginState.get().address;
    userSessions[jwt] = { address, walletId: wallet! };

    res.json({ jwt, address });
  } catch (error) {
    res.status(500).json({ error: 'Authentication failed' });
  }
});



// Helper function to exchange code for JWT (custom implementation)
async function exchangeCodeForJwt(code: string, state: string): Promise<string> {
    // Enoki doesn't provide a direct server-side code exchange method in the SDK
    // Implement OAuth code exchange with Google's token endpoint
    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID || '',
        client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
        redirect_uri: 'http://localhost:3000/auth/callback',
        grant_type: 'authorization_code',
      }).toString(),
    });
  
    const data = await response.json();
    if (data.error) {
      throw new Error(data.error_description);
    }
  
    // Extract ID token (JWT) from response
    return data.id_token;
  }



// Sign and sponsor transaction
app.post('/api/sign-transaction', async (req, res) => {
  const { jwt, transaction } = req.body;
  const session = userSessions[jwt];
  const flow = new EnokiFlow({apiKey: "enoki_public_10094b0bafc9ba2626fcbc02a1812d6b"});

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    // const { signature, transactionBlock } = await flow. signTransaction({
    //   walletId: session.walletId,
    //   transaction,
    // });
    const txBytes = await transaction.build({ client: suiClient });
    const signer = await flow.getKeypair({
        network: "mainnet",
      });
      const signature = await signer.signTransaction(txBytes);

    // Sponsor and execute transaction
    // const result = await flow.executeTransaction({
    //   bytes: signature,
    //   network: 'mainnet',
    // });
    await suiClient.executeTransactionBlock({
        transactionBlock: txBytes,
        signature: signature!.signature,
        requestType: "WaitForLocalExecution",
        options: {},
      }).then((result) => {
        //   callback(result);
        //   console.log("lllllll");
          console.log(result.digest);
          res.json({ result });
      }).catch(e => {
        //   if(errorCallback){
        //       errorCallback(e);
        //   }
          console.log(e);
      });
    
  } catch (error) {
    res.status(500).json({ error: 'Transaction failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});