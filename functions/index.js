const PORT = process.env.PORT || 3001;
// Import necessary modules for Firebase Functions, Admin SDK, Express, CORS, and node-fetch
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

// Initialize the Firebase Admin SDK. It automatically uses project credentials when deployed.
admin.initializeApp();

// Create an Express app to handle API requests
const app = express();

// Enable Cross-Origin Resource Sharing (CORS).
// For production, you should restrict the origin to your app's specific domain for better security.
app.use(cors({ origin: true }));

/**
 * Middleware to authenticate requests using Firebase ID tokens.
 * It checks for a 'Bearer' token in the Authorization header, verifies it,
 * and attaches the decoded user information to the request object.
 */
const authenticate = async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    console.error('No Firebase ID token was passed as a Bearer token in the Authorization header.');
    res.status(403).send({ error: 'Unauthorized: No token provided.' });
    return;
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
/**
 * A special function for the designated owner to claim the initial admin role.
 * This should only need to be run once.
 */
app.post('/claim-admin-role', authenticate, async (req, res) => {
    // Securely get the owner's email from Firebase environment configuration.
    const ownerEmail = functions.config().owner?.email;

    if (!ownerEmail) {
        console.error('OWNER_EMAIL is not set in Firebase function configuration.');
        return res.status(500).send({ error: 'Server configuration error: Owner email not set.' });
    }

    // Check if the person calling this function is the designated owner.
    if (req.user.email !== ownerEmail) {
        return res.status(403).send({ error: 'Forbidden: Only the designated owner can claim the admin role.' });
    }
    
    // Grant the admin custom claim.
    try {
        await admin.auth().setCustomUserClaims(req.user.uid, { admin: true });
        return res.status(200).send({ message: `Success! You (${req.user.email}) have been granted admin privileges. Please refresh the page.` });
    } catch (error) {
        console.error('Error granting initial admin role:', error);
        return res.status(500).send({ error: 'Failed to grant admin role.' });
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

  // Securely retrieve the GitHub token from Firebase environment configuration.
  const githubToken = functions.config().github?.token;
  if (!githubToken) {
    console.error('GitHub token is not set in Firebase function configuration.');
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
 */
app.post('/grant-admin-role', async (req, res) => {
  // SECURITY CHECK: Verify that the user making the request is already an admin.
  if (req.user.admin !== true) {
    return res.status(403).send({ error: 'Forbidden: Only admins can grant admin roles.' });
  }

  const { email } = req.body;
  if (!email) {
    return res.status(400).send({ error: 'Missing email in request body.' });
  }

  try {
    const userToMakeAdmin = await admin.auth().getUserByEmail(email);
    await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { admin: true });
    return res.status(200).send({ message: `Success! ${email} has been made an admin.` });
  } catch (error) {
    console.error('Error granting admin role:', error);
    return res.status(500).send({ error: 'Failed to grant admin role.' });
  }
});

// Expose the Express app as a single Cloud Function named 'api'.
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
