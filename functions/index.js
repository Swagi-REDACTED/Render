const PORT = process.env.PORT || 3001;
// Import necessary modules
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

// --- Firebase Admin SDK Initialization ---
try {
  const serviceAccount = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("Firebase Admin SDK initialized successfully.");
} catch (error) {
  console.error("Failed to initialize Firebase Admin SDK.", error);
}

// --- Render API Helper Functions ---
// IMPORTANT: For these functions to work, you MUST set the following
// environment variables in your Render project settings:
// 1. RENDER_API_KEY: Your personal Render API key.
// 2. RENDER_SERVICE_ID: The ID of this service on Render.
// 3. ADMIN_EMAILS: A comma-separated list of initial admin emails.

const RENDER_API_KEY = process.env.RENDER_API_KEY;
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID;
const RENDER_API_URL = `https://api.render.com/v1/services/${RENDER_SERVICE_ID}/env-vars`;

/**
 * Fetches all environment variables from the Render service and formats them correctly.
 * @returns {Promise<Array>} A promise that resolves to an array of {key, value} objects.
 */
async function getRenderEnvVars() {
    if (!RENDER_API_KEY || !RENDER_SERVICE_ID) {
        throw new Error('Render API key or Service ID is not configured on the server.');
    }
    const response = await fetch(RENDER_API_URL, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${RENDER_API_KEY}`,
            'Accept': 'application/json',
        },
    });
    if (!response.ok) {
        const errorBody = await response.json();
        console.error("Render API Error (getRenderEnvVars):", errorBody);
        throw new Error('Failed to fetch environment variables from Render.');
    }
    const rawVars = await response.json();
    // ✅ FIXED: Map the complex response from Render's GET endpoint to the simple
    // {key, value} format required by the PUT endpoint. Also, filter out any
    // potential variables that might not have a key to prevent errors.
    return rawVars.map(item => ({
        key: item.envVar.key,
        value: item.envVar.value,
    })).filter(v => v.key);
}


/**
 * Updates the environment variables on the Render service.
 * This will trigger a new deployment on Render.
 * @param {Array} envVars - The array of {key, value} objects to set.
 * @returns {Promise<Object>} A promise that resolves to the response from the Render API.
 */
async function updateRenderEnvVars(envVars) {
    if (!RENDER_API_KEY || !RENDER_SERVICE_ID) {
        throw new Error('Render API key or Service ID is not configured on the server.');
    }
    const response = await fetch(RENDER_API_URL, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${RENDER_API_KEY}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(envVars),
    });
    if (!response.ok) {
        const errorBody = await response.json();
        console.error("Render API Error (updateRenderEnvVars):", errorBody);
        throw new Error('Failed to update environment variables on Render.');
    }
    return response.json();
}


// --- Express App Setup ---
const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

// --- Authentication Middleware ---
const authenticate = async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    return res.status(403).send({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = req.headers.authorization.split('Bearer ')[1];
  try {
    req.user = await admin.auth().verifyIdToken(idToken);
    next();
  } catch (error) {
    res.status(403).send({ error: 'Unauthorized: Invalid token.' });
  }
};

// --- PUBLIC GITHUB PROXY ROUTE ---
app.post('/github-proxy', async (req, res) => {
  const { githubApiUrl, method = 'GET', body = null } = req.body;
  if (!githubApiUrl) return res.status(400).send({ error: 'Missing githubApiUrl' });
  const githubToken = process.env.GITHUB_TOKEN;
  if (!githubToken) return res.status(500).send({ error: 'Server configuration error' });
  try {
    const fetchOptions = {
      method: method,
      headers: { 'Authorization': `Bearer ${githubToken}`, 'Accept': 'application/vnd.github.v3+json', 'Content-Type': 'application/json' },
    };
    if (body) fetchOptions.body = JSON.stringify(body);
    const githubResponse = await fetch(githubApiUrl, fetchOptions);
    const data = await githubResponse.json();
    res.status(githubResponse.status).json(data);
  } catch (error) {
    res.status(500).send({ error: 'Internal Server Error' });
  }
});

// Secure all following routes
app.use(authenticate);

// --- OWNER-ONLY ROUTES ---
app.post('/claim-admin-role', async (req, res) => {
    if (req.user.email !== process.env.OWNER_EMAIL) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can perform this action.' });
    }
    try {
        await admin.auth().setCustomUserClaims(req.user.uid, { admin: true, owner: true });
        res.status(200).send({ message: 'Success! You have been granted owner & admin privileges.' });
    } catch (error) {
        console.error('Error granting initial owner role:', error);
        res.status(500).send({ error: 'Failed to grant owner role.' });
    }
});

app.post('/grant-admin-role', async (req, res) => {
    if (req.user.owner !== true) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can grant admin roles.' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).send({ error: 'Missing email.' });
    if (email === process.env.OWNER_EMAIL) return res.status(400).send({ error: "Cannot change the owner's roles." });

    try {
        // Step 1: Set the custom claim in Firebase
        const userToMakeAdmin = await admin.auth().getUserByEmail(email);
        const existingClaims = (await admin.auth().getUser(userToMakeAdmin.uid)).customClaims || {};
        await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { ...existingClaims, admin: true });

        // Step 2: Update the ADMIN_EMAILS environment variable on Render
        const envVars = await getRenderEnvVars();
        const adminEmailsVar = envVars.find(v => v.key === 'ADMIN_EMAILS');
        
        if (adminEmailsVar) {
            let emails = adminEmailsVar.value ? adminEmailsVar.value.split(',').map(e => e.trim()).filter(e => e) : [];
            if (!emails.includes(email)) {
                emails.push(email);
                adminEmailsVar.value = emails.join(',');
            }
        } else {
            // This case should not be hit if the user sets the ADMIN_EMAILS var, but is a fallback.
            envVars.push({ key: 'ADMIN_EMAILS', value: email });
        }
        
        await updateRenderEnvVars(envVars);

        res.status(200).send({ message: `Success! ${email} is now an admin. The server is restarting with new permissions.` });

    } catch (error) {
        console.error('Error in grant-admin-role:', error);
        res.status(500).send({ error: error.message || 'Failed to grant admin role.' });
    }
});

app.post('/revoke-admin-role', async (req, res) => {
    if (req.user.owner !== true) {
        return res.status(403).send({ error: 'Forbidden: Only the owner can revoke admin roles.' });
    }
    const { email } = req.body;
    if (!email) return res.status(400).send({ error: 'Missing email.' });
    if (email === process.env.OWNER_EMAIL) return res.status(400).send({ error: 'Cannot revoke the owner\'s admin role.' });

    try {
        // Step 1: Revoke custom claim in Firebase
        const userToRevoke = await admin.auth().getUserByEmail(email);
        const existingClaims = (await admin.auth().getUser(userToRevoke.uid)).customClaims || {};
        delete existingClaims.admin; // Remove only the admin claim
        await admin.auth().setCustomUserClaims(userToRevoke.uid, existingClaims);

        // Step 2: Update the ADMIN_EMAILS environment variable on Render
        const envVars = await getRenderEnvVars();
        const adminEmailsVar = envVars.find(v => v.key === 'ADMIN_EMAILS');
        
        if (adminEmailsVar && adminEmailsVar.value) {
            let emails = adminEmailsVar.value.split(',').map(e => e.trim());
            const initialLength = emails.length;
            emails = emails.filter(e => e !== email);

            if (emails.length < initialLength) {
                adminEmailsVar.value = emails.join(',');
                await updateRenderEnvVars(envVars);
            }
        }

        res.status(200).send({ message: `Success! Admin role for ${email} has been revoked. The server is restarting.` });

    } catch (error) {
        console.error('Error in revoke-admin-role:', error);
        res.status(500).send({ error: error.message || 'Failed to revoke admin role.' });
    }
});

// Start the Express server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
