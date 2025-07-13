const PORT = process.env.PORT || 3001;
// Import necessary modules
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

// --- Firebase Admin SDK Initialization ---
// IMPORTANT: Your GOOGLE_APPLICATION_CREDENTIALS_JSON must be set in your Render environment.
try {
  const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("Firebase Admin SDK initialized successfully.");
} catch (error) {
  console.error("Failed to initialize Firebase Admin SDK. Ensure GOOGLE_APPLICATION_CREDENTIALS_JSON is set correctly.", error);
  // Exit if Firebase can't initialize, as the app is non-functional without it.
  process.exit(1); 
}

// --- Express App Setup ---
const app = express();
// Only allow your specific Firebase hosting domain to connect.
const corsOptions = {
  origin: 'https://blu-free-file-hosting.firebaseapp.com',
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// --- Authentication Middleware ---
// This middleware verifies the Firebase JWT on incoming requests.
const authenticate = async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    return res.status(403).send({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = req.headers.authorization.split('Bearer ')[1];
  try {
    // verifyIdToken() checks the token's validity and returns the decoded claims.
    req.user = await admin.auth().verifyIdToken(idToken);
    next();
  } catch (error) {
    res.status(403).send({ error: 'Unauthorized: Invalid token.' });
  }
};

// --- PUBLIC GITHUB PROXY ROUTE ---
// This route safely proxies requests to the GitHub API using your secret token.
app.post('/github-proxy', async (req, res) => {
  const { githubApiUrl } = req.body;
  if (!githubApiUrl || !githubApiUrl.startsWith('https://api.github.com/')) {
    return res.status(400).send({ error: 'A valid GitHub API URL is required.' });
  }

  const githubToken = process.env.GITHUB_TOKEN;
  if (!githubToken) {
    console.error("GITHUB_TOKEN is not configured on the server.");
    return res.status(500).send({ error: 'Server configuration error.' });
  }

  try {
    const fetchOptions = {
      method: 'GET', // Only allow GET requests for this proxy
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github.v3+json'
      },
    };
    
    const githubResponse = await fetch(githubApiUrl, fetchOptions);
    
    if (!githubResponse.ok) {
        const errorData = await githubResponse.json();
        return res.status(githubResponse.status).json(errorData);
    }

    const data = await githubResponse.json();
    res.status(200).json(data);

  } catch (error) {
    console.error('GitHub Proxy Error:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// Authenticate all routes defined below this line
app.use(authenticate);

// --- OWNER-ONLY ROUTES ---

// Endpoint for the designated owner to claim their role for the first time.
app.post('/claim-owner-role', async (req, res) => {
    // Logic is now secure: checks the authenticated user's email against a server-side env var.
    // The owner's email is NEVER exposed to the client.
    if (req.user.email !== process.env.OWNER_EMAIL) {
        return res.status(403).send({ error: 'Forbidden: This action is restricted to the owner.' });
    }
    
    // Check if user already has the owner claim
    if (req.user.owner === true) {
        return res.status(200).send({ message: 'You are already the owner.' });
    }

    try {
        // Set custom claims to grant owner and admin privileges.
        await admin.auth().setCustomUserClaims(req.user.uid, { admin: true, owner: true });
        res.status(200).send({ message: 'Success! You have been granted owner & admin privileges. Please refresh.' });
    } catch (error) {
        console.error('Error granting owner role:', error);
        res.status(500).send({ error: 'Failed to grant owner role.' });
    }
});

// Endpoint for the owner to grant admin privileges to another user.
app.post('/grant-admin-role', async (req, res) => {
    // Only a user with the 'owner' claim can access this.
    if (req.user.owner !== true) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can grant admin roles.' });
    }

    const { email } = req.body;
    if (!email) {
        return res.status(400).send({ error: 'User email is required.' });
    }
    if (email === process.env.OWNER_EMAIL) {
        return res.status(400).send({ error: "Cannot change the owner's roles." });
    }

    try {
        const userToMakeAdmin = await admin.auth().getUserByEmail(email);
        // Safely add the admin claim without affecting other potential claims.
        const existingClaims = userToMakeAdmin.customClaims || {};
        await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { ...existingClaims, admin: true });
        res.status(200).send({ message: `Success! ${email} is now an admin.` });
    } catch (error) {
        console.error('Error in grant-admin-role:', error);
        res.status(500).send({ error: error.message || 'Failed to grant admin role.' });
    }
});

// Endpoint for the owner to revoke admin privileges from a user.
app.post('/revoke-admin-role', async (req, res) => {
    if (req.user.owner !== true) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can revoke admin roles.' });
    }

    const { email } = req.body;
    if (!email) {
        return res.status(400).send({ error: 'User email is required.' });
    }
    if (email === process.env.OWNER_EMAIL) {
        return res.status(400).send({ error: 'Cannot revoke the owner\'s admin role.' });
    }

    try {
        const userToRevoke = await admin.auth().getUserByEmail(email);
        const existingClaims = userToRevoke.customClaims || {};
        // Securely remove only the admin claim.
        delete existingClaims.admin;
        await admin.auth().setCustomUserClaims(userToRevoke.uid, existingClaims);
        res.status(200).send({ message: `Success! Admin role for ${email} has been revoked.` });
    } catch (error) {
        console.error('Error in revoke-admin-role:', error);
        res.status(500).send({ error: error.message || 'Failed to revoke admin role.' });
    }
});


// Start the Express server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
