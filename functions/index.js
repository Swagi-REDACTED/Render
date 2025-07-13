const PORT = process.env.PORT || 3001;
// Import necessary modules
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

// --- IMPORTANT: Initialize Firebase Admin SDK for a server environment ---
// This requires a service account key provided as an environment variable.
try {
  const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("Firebase Admin SDK initialized successfully.");
} catch (error)
{
  console.error("Failed to initialize Firebase Admin SDK. Ensure GOOGLE_APPLICATION_CREDENTIALS_JSON is set correctly.", error);
}

// Create an Express app to handle API requests
const app = express();

// Enable Cross-Origin Resource Sharing (CORS)
app.use(cors({ origin: true }));
app.use(express.json()); // Middleware to parse JSON bodies

/**
 * Middleware to authenticate requests using Firebase ID tokens.
 */
const authenticate = async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    return res.status(403).send({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = req.headers.authorization.split('Bearer ')[1];
  try {
    const decodedIdToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedIdToken;
    next();
  } catch (error) {
    console.error('Error while verifying Firebase ID token:', error);
    res.status(403).send({ error: 'Unauthorized: Invalid token.' });
  }
};


// --- OWNER-ONLY FUNCTION TO CLAIM THE FIRST ADMIN ROLE ---
app.post('/claim-admin-role', authenticate, async (req, res) => {
    const ownerEmail = process.env.OWNER_EMAIL;

    if (!ownerEmail) {
        console.error('OWNER_EMAIL is not set in environment variables.');
        return res.status(500).send({ error: 'Server configuration error: Owner email not set.' });
    }

    if (req.user.email !== ownerEmail) {
        return res.status(403).send({ error: 'Forbidden: Only the designated owner can claim the admin role.' });
    }
    
    try {
        // UPDATED: Set both admin and owner claims for the owner.
        await admin.auth().setCustomUserClaims(req.user.uid, { admin: true, owner: true });
        return res.status(200).send({ message: `Success! You (${req.user.email}) have been granted owner & admin privileges.` });
    } catch (error) {
        console.error('Error granting initial owner role:', error);
        return res.status(500).send({ error: 'Failed to grant owner role.' });
    }
});


// Apply the authentication middleware to all subsequent routes.
app.use(authenticate);

/**
 * Route to act as a secure proxy for the GitHub API.
 */
app.post('/github-proxy', async (req, res) => {
  const { githubApiUrl, method = 'GET', body = null } = req.body;

  if (!githubApiUrl) {
    return res.status(400).send({ error: 'Missing githubApiUrl in request body.' });
  }

  const githubToken = process.env.GITHUB_TOKEN;
  if (!githubToken) {
    console.error('GITHUB_TOKEN is not set in environment variables.');
    return res.status(500).send({ error: 'Server configuration error: GitHub token not set.' });
  }

  try {
    const fetchOptions = {
      method: method,
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      },
    };

    if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
      fetchOptions.body = JSON.stringify(body);
    }

    const githubResponse = await fetch(githubApiUrl, fetchOptions);
    const data = await githubResponse.json();
    res.status(githubResponse.status).json(data);
  } catch (error) {
    console.error('Error proxying request to GitHub:', error);
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

/**
 * Administrative route to grant another user an 'admin' role.
 * Only the owner can perform this action.
 */
app.post('/grant-admin-role', async (req, res) => {
  // UPDATED: Check for owner claim, not just admin.
  if (req.user.owner !== true) {
    return res.status(403).send({ error: 'Forbidden: Only the owner can grant admin roles.' });
  }

  const { email } = req.body;
  if (!email) {
    return res.status(400).send({ error: 'Missing email in request body.' });
  }

  if (email === process.env.OWNER_EMAIL) {
      return res.status(400).send({ error: "Cannot change the owner's roles." });
  }

  try {
    const userToMakeAdmin = await admin.auth().getUserByEmail(email);
    // Set only the admin claim for the new admin.
    await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { admin: true });
    return res.status(200).send({ message: `Success! ${email} has been made an admin.` });
  } catch (error) {
    console.error('Error granting admin role:', error);
    return res.status(500).send({ error: 'Failed to grant admin role.' });
  }
});

/**
 * NEW: Administrative route to REVOKE a user's 'admin' role.
 * Only the owner can perform this action.
 */
app.post('/revoke-admin-role', async (req, res) => {
    // Check for owner claim.
    if (req.user.owner !== true) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can revoke admin roles.' });
    }

    const { email } = req.body;
    if (!email) {
        return res.status(400).send({ error: 'Missing email in request body.' });
    }
    
    // The owner cannot revoke their own admin status.
    if (email === process.env.OWNER_EMAIL) {
        return res.status(400).send({ error: 'Owner cannot revoke their own admin role.' });
    }

    try {
        const userToRevoke = await admin.auth().getUserByEmail(email);
        // Revoke claims by setting them to an empty object.
        await admin.auth().setCustomUserClaims(userToRevoke.uid, {});
        return res.status(200).send({ message: `Success! Admin role for ${email} has been revoked.` });
    } catch (error) {
        console.error('Error revoking admin role:', error);
        return res.status(500).send({ error: 'Failed to remove admin role.' });
    }
});

// Start the Express server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
