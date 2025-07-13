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

const db = admin.firestore();
const configDocRef = db.collection('appConfig').doc('main');

// --- GitHub Caching Service ---

/**
 * Fetches the entire file tree for a single repository recursively.
 * @param {string} user - The GitHub username.
 * @param {string} repoName - The repository name.
 * @param {string} branch - The branch to fetch.
 * @param {string} token - The GitHub API token.
 * @returns {Promise<Array|null>} A promise that resolves to the repository's file tree or null.
 */
async function fetchRepoTreeRecursive(user, repoName, branch, token) {
    const url = `https://api.github.com/repos/${user}/${repoName}/git/trees/${branch}?recursive=1`;
    try {
        const response = await fetch(url, { headers: { 'Authorization': `Bearer ${token}` } });
        if (!response.ok) {
            console.error(`Failed to fetch tree for ${repoName}: ${response.statusText}`);
            return null;
        }
        const data = await response.json();
        if (data.truncated) {
            console.warn(`Warning: File tree for ${repoName} was truncated. Some files may be missing.`);
        }
        // Add a direct download_url to each file for easy access on the frontend
        return data.tree.map(item => ({
            ...item,
            download_url: item.type === 'blob' ? `https://raw.githubusercontent.com/${user}/${repoName}/${branch}/${item.path}` : null
        }));
    } catch (error) {
        console.error(`Error in fetchRepoTreeRecursive for ${repoName}:`, error);
        return null;
    }
}

/**
 * Iterates through all tracked repositories and updates their cached file trees in Firestore.
 */
async function syncAllTrackedRepos() {
    console.log('Starting GitHub repository sync...');
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
        console.error('GITHUB_TOKEN is not set. Cannot sync repositories.');
        return;
    }

    try {
        const docSnap = await configDocRef.get();
        if (!docSnap.exists) {
            console.log('Config document does not exist. Skipping sync.');
            return;
        }

        const config = docSnap.data();
        const user = config.githubUser;
        // Make a deep copy to avoid mutation issues
        const trackedRepos = JSON.parse(JSON.stringify(config.trackedRepos || []));

        if (!user || trackedRepos.length === 0) {
            console.log('No GitHub user or tracked repos configured. Skipping sync.');
            return;
        }

        for (const repo of trackedRepos) {
            console.log(`- Syncing ${repo.name}...`);
            const tree = await fetchRepoTreeRecursive(user, repo.name, repo.branch, token);
            if (tree) {
                repo.tree = tree; // Store the cached tree on the repo object
                console.log(`- Successfully synced ${repo.name} with ${tree.length} items.`);
            }
        }

        await configDocRef.update({ trackedRepos });
        console.log('GitHub repository sync completed successfully.');
    } catch (error) {
        console.error('An error occurred during syncAllTrackedRepos:', error);
    }
}

// Schedule the sync to run every 24 hours and also run it once on startup.
setInterval(syncAllTrackedRepos, 24 * 60 * 60 * 1000);
setTimeout(syncAllTrackedRepos, 10000); // Run 10s after server start to allow for initialization


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

// All routes after this line are protected
app.use(authenticate);

// --- Admin-Only Routes ---

// Proxy for admins to fetch their full list of repos for management
app.get('/admin/github-proxy', async (req, res) => {
    if (!req.user.admin) return res.status(403).send({ error: 'Forbidden' });
    const { url } = req.query;
    const token = req.headers['x-github-token'];
    if (!url || !token) return res.status(400).send({ error: 'Missing URL or GitHub Token' });

    try {
        const response = await fetch(url, { headers: { 'Authorization': `Bearer ${token}` } });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (error) {
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Endpoint to manually trigger the repository sync
app.post('/admin/sync-github', async (req, res) => {
    if (!req.user.admin) return res.status(403).send({ error: 'Forbidden' });
    
    // Run async in the background, don't wait for it to finish
    syncAllTrackedRepos();
    res.status(202).send({ message: 'GitHub sync started successfully. Data will update shortly.' });
});

// --- Owner-Only User Management ---
app.get('/admin/users', async (req, res) => {
    if (!req.user.owner) return res.status(403).send({ error: 'Forbidden' });
    try {
        const listUsersResult = await admin.auth().listUsers(1000);
        const users = listUsersResult.users.map(user => ({
            uid: user.uid,
            email: user.email,
            isAdmin: !!user.customClaims?.admin,
            isOwner: !!user.customClaims?.owner,
        }));
        res.status(200).json(users);
    } catch (error) {
        res.status(500).send({ error: 'Failed to list users.' });
    }
});

app.post('/admin/set-role', async (req, res) => {
    if (!req.user.owner) return res.status(403).send({ error: 'Forbidden' });
    const { uid, isAdmin } = req.body;
    try {
        const user = await admin.auth().getUser(uid);
        if (user.customClaims?.owner) {
            return res.status(400).send({ error: "Cannot change the owner's roles." });
        }
        await admin.auth().setCustomUserClaims(uid, { ...user.customClaims, admin: isAdmin });
        res.status(200).send({ message: 'User role updated successfully.' });
    } catch (error) {
        res.status(500).send({ error: 'Failed to set user role.' });
    }
});


// Start the Express server
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
