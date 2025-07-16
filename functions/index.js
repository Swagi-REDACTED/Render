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

async function fetchFromGitHub(apiUrl, token) {
    const response = await fetch(apiUrl, { headers: { 'Authorization': `Bearer ${token}` } });
    if (!response.ok) {
        const errorBody = await response.json().catch(() => ({ message: response.statusText }));
        throw new Error(`GitHub API Error: ${response.status} - ${errorBody.message}`);
    }
    return response.json();
}

/**
 * Fetches all necessary data for a repository (all branches and their trees) and caches it.
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
        if (!docSnap.exists) { console.log('Config document does not exist. Skipping sync.'); return; }

        const config = docSnap.data();
        const user = config.githubUser;
        const trackedRepos = JSON.parse(JSON.stringify(config.trackedRepos || []));

        if (!user || trackedRepos.length === 0) { console.log('No GitHub user or tracked repos configured. Skipping sync.'); return; }

        for (const repo of trackedRepos) {
            console.log(`- Syncing ${repo.name}...`);
            try {
                const branchesData = await fetchFromGitHub(`https://api.github.com/repos/${user}/${repo.name}/branches`, token);
                repo.branches = branchesData.map(b => b.name);
                repo.builds = {}; // Reset builds to ensure clean sync

                for (const branchName of repo.branches) {
                    console.log(`  - Syncing branch: ${branchName}`);
                    const treeData = await fetchFromGitHub(`https://api.github.com/repos/${user}/${repo.name}/git/trees/${branchName}?recursive=1`, token);
                    if (treeData.truncated) {
                        console.warn(`  - WARNING: File tree for ${repo.name}#${branchName} was truncated.`);
                    }
                    repo.builds[branchName] = {
                        tree: treeData.tree.map(item => ({
                            ...item,
                            download_url: item.type === 'blob' ? `https://raw.githubusercontent.com/${user}/${repo.name}/${branchName}/${item.path}` : null
                        }))
                    };
                }
                console.log(`- Successfully synced ${repo.name} with ${repo.branches.length} builds.`);

            } catch (error) {
                console.error(`- Failed to sync ${repo.name}: ${error.message}`);
            }
        }

        await configDocRef.update({ trackedRepos });
        console.log('GitHub repository sync completed successfully.');
    } catch (error) {
        console.error('An error occurred during syncAllTrackedRepos:', error);
    }
}

setInterval(syncAllTrackedRepos, 24 * 60 * 60 * 1000);
setTimeout(syncAllTrackedRepos, 10000);

// --- Express App Setup & Middleware ---
const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const authenticate = async (req, res, next) => {
  if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
    return res.status(403).send({ error: 'Unauthorized: No token provided.' });
  }
  const idToken = req.headers.authorization.split('Bearer ')[1];
  try {
    req.user = await admin.auth().verifyIdToken(idToken);
    if (req.user.email === process.env.OWNER_EMAIL && !req.user.owner) {
        req.user.is_owner_unclaimed = true;
    }
    next();
  } catch (error) {
    res.status(403).send({ error: 'Unauthorized: Invalid token.' });
  }
};

app.use(authenticate);

// --- User-facing Routes ---

app.post('/vote', async (req, res) => {
    const { itemId, itemType, direction } = req.body;
    const userId = req.user.uid;
    if (!itemId || !itemType || !['up', 'down'].includes(direction)) {
        return res.status(400).send({ error: 'Missing or invalid voting information.' });
    }

    const voteDocRef = db.collection('votes').doc(`${userId}_${itemId}`);
    const value = direction === 'up' ? 1 : -1;

    try {
        await db.runTransaction(async (transaction) => {
            const voteDoc = await transaction.get(voteDocRef);
            const configDoc = await transaction.get(configDocRef);
            if (!configDoc.exists()) { throw new Error("Config document does not exist!"); }
            
            const configData = configDoc.data();
            const isMega = itemType === 'mega';
            
            let items = isMega ? (configData.megaProjects || []) : (configData.trackedRepos || []);
            const itemIndex = items.findIndex(p => (isMega ? p.id : p.name) === itemId);
            if (itemIndex === -1) { throw new Error("Item not found!"); }

            let currentVote = 0;
            if (voteDoc.exists()) {
                currentVote = voteDoc.data().value;
            }

            let repChange = 0;
            if (currentVote === value) { // User is clicking the same button again (undo vote)
                repChange = -value;
                transaction.delete(voteDocRef);
            } else { // New vote or changing vote
                repChange = value - currentVote; // This correctly calculates the change (e.g., from -1 to 1 is a +2 change)
                transaction.set(voteDocRef, { userId, itemId, value });
            }
            
            items[itemIndex].rep = (items[itemIndex].rep || 0) + repChange;
            
            if (isMega) {
                transaction.update(configDocRef, { megaProjects: items });
            } else {
                transaction.update(configDocRef, { trackedRepos: items });
            }
        });
        res.status(200).send({ message: 'Vote recorded.' });
    } catch (error) {
        console.error("Vote transaction failed: ", error);
        res.status(500).send({ error: "Your vote could not be recorded." });
    }
});

app.post('/report', async (req, res) => {
    const { itemId, itemType, reportType, details } = req.body;
    const { uid, email } = req.user;

    if (!itemId || !itemType || !reportType || !details) {
        return res.status(400).send({ error: 'Missing required report information.' });
    }

    try {
        await db.collection('reports').add({
            userId: uid,
            userEmail: email,
            itemId,
            itemType,
            reportType,
            details,
            status: 'new',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        res.status(200).send({ message: 'Report submitted successfully!' });
    } catch (error) {
        console.error("Failed to submit report:", error);
        res.status(500).send({ error: 'Failed to submit report.' });
    }
});


// --- Admin-Only Routes ---

app.delete('/report/:reportId', async (req, res) => {
    if (!req.user.admin) return res.status(403).send({ error: 'Forbidden' });
    const { reportId } = req.params;
    if (!reportId) return res.status(400).send({ error: 'Missing report ID.' });

    try {
        const reportRef = db.collection('reports').doc(reportId);
        await reportRef.delete();
        res.status(200).send({ message: 'Report deleted successfully.' });
    } catch (error) {
        console.error("Failed to delete report:", error);
        res.status(500).send({ error: 'Failed to delete report.' });
    }
});

app.get('/admin/github-repos', async (req, res) => {
    if (!req.user.admin) return res.status(403).send({ error: 'Forbidden' });
    const { user } = req.query;
    if (!user) return res.status(400).send({ error: 'Missing GitHub username' });
    
    const token = process.env.GITHUB_TOKEN;
    if (!token) return res.status(500).send({ error: 'Server configuration error' });

    try {
        const repos = await fetchFromGitHub(`https://api.github.com/users/${user}/repos?per_page=100`, token);
        res.status(200).json(repos);
    } catch (error) {
        res.status(500).send({ error: error.message });
    }
});

app.post('/admin/sync-github', async (req, res) => {
    if (!req.user.admin) return res.status(403).send({ error: 'Forbidden' });
    syncAllTrackedRepos();
    res.status(202).send({ message: 'GitHub sync started. Data will update shortly.' });
});

// --- Owner-Only User Management ---
app.post('/claim-owner-role', async (req, res) => {
    if (req.user.email !== process.env.OWNER_EMAIL) {
        return res.status(403).send({ error: 'Forbidden: Only the designated owner can perform this action.' });
    }
    try {
        await admin.auth().setCustomUserClaims(req.user.uid, { admin: true, owner: true });
        res.status(200).send({ message: 'Success! You have been granted owner & admin privileges.' });
    } catch (error) {
        res.status(500).send({ error: 'Failed to grant owner role.' });
    }
});

app.post('/grant-admin-role', async (req, res) => {
    if (!req.user.owner) return res.status(403).send({ error: 'Forbidden' });
    const { email } = req.body;
    if (!email) return res.status(400).send({ error: 'Missing email.' });
    try {
        const userToMakeAdmin = await admin.auth().getUserByEmail(email);
        await admin.auth().setCustomUserClaims(userToMakeAdmin.uid, { admin: true });
        res.status(200).send({ message: `Success! ${email} is now an admin.` });
    } catch (error) {
        res.status(500).send({ error: error.message || 'Failed to grant admin role.' });
    }
});

app.post('/revoke-admin-role', async (req, res) => {
    if (!req.user.owner) return res.status(403).send({ error: 'Forbidden' });
    const { email } = req.body;
    if (!email) return res.status(400).send({ error: 'Missing email.' });
    if (email === process.env.OWNER_EMAIL) return res.status(400).send({ error: "Cannot revoke the owner's admin role." });
    try {
        const userToRevoke = await admin.auth().getUserByEmail(email);
        await admin.auth().setCustomUserClaims(userToRevoke.uid, null);
        res.status(200).send({ message: `Success! Admin role for ${email} has been revoked.` });
    } catch (error) {
        res.status(500).send({ error: error.message || 'Failed to revoke admin role.' });
    }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
