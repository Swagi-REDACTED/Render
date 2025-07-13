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

// --- Render API Helper Functions (No changes here) ---
const RENDER_API_KEY = process.env.RENDER_API_KEY;
const RENDER_SERVICE_ID = process.env.RENDER_SERVICE_ID;
const RENDER_API_URL = `https://api.render.com/v1/services/${RENDER_SERVICE_ID}/env-vars`;

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
    return rawVars.map(item => ({
        key: item.envVar.key,
        value: item.envVar.value,
    })).filter(v => v.key);
}

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

// All routes after this line are protected by authentication
app.use(authenticate);

// --- 🔒 SECURED GITHUB PROXY ROUTE ---
// Changed from app.post to app.get and now reads from req.query
app.get('/github-proxy', async (req, res) => {
  const { url } = req.query; // ✅ FIXED: Read from query parameter
  if (!url) {
    return res.status(400).send({ error: 'Missing GitHub API URL in query parameter.' });
  }

  const githubToken = process.env.GITHUB_TOKEN;
  if (!githubToken) {
    return res.status(500).send({ error: 'Server configuration error: GITHUB_TOKEN not set.' });
  }

  try {
    const fetchOptions = {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github.v3+json',
      },
    };

    const githubResponse = await fetch(url, fetchOptions);
    const data = await githubResponse.json();

    // Forward GitHub's status and response directly to the client
    res.status(githubResponse.status).json(data);
  } catch (error) {
    console.error('Error in GitHub proxy:', error);
    res.status(500).send({ error: 'Internal Server Error while contacting GitHub.' });
  }
});


// --- OWNER-ONLY ROUTES (No changes needed below this line) ---
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
        const userToMakeAdmin = await admin.auth().getUserByEmail(email);
        const existingClaims = (await admin.auth().getUser(userToMakeAdmin.uid)).customClaims || {};
        await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { ...existingClaims, admin: true });
        const envVars = await getRenderEnvVars();
        const adminEmailsVar = envVars.find(v => v.key === 'ADMIN_EMAILS');
        if (adminEmailsVar) {
            let emails = adminEmailsVar.value ? adminEmailsVar.value.split(',').map(e => e.trim()).filter(e => e) : [];
            if (!emails.includes(email)) {
                emails.push(email);
                adminEmailsVar.value = emails.join(',');
            }
        } else {
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
        const userToRevoke = await admin.auth().getUserByEmail(email);
        const existingClaims = (await admin.auth().getUser(userToRevoke.uid)).customClaims || {};
        delete existingClaims.admin;
        await admin.auth().setCustomUserClaims(userToRevoke.uid, existingClaims);
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
