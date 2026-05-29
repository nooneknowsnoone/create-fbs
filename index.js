const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const { v4: uuidv4 } = require('uuid');
const os = require('os');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== DATABASE SETUP (SQLite) ====================
const Database = require('better-sqlite3');
const db = new Database(path.join(__dirname, 'accounts.db'));

// Initialize database tables
db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    api_key TEXT UNIQUE NOT NULL,
    api_secret TEXT NOT NULL,
    name TEXT,
    permissions TEXT DEFAULT 'create,read',
    rate_limit INTEGER DEFAULT 100,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME,
    is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    email TEXT,
    password TEXT,
    first_name TEXT,
    last_name TEXT,
    birthday TEXT,
    gender TEXT,
    profile_link TEXT,
    api_key_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY(api_key_id) REFERENCES api_keys(id)
  );

  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id TEXT,
    action TEXT,
    ip TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS temp_emails (
    email TEXT PRIMARY KEY,
    api_key_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  );
`);

// ==================== CONFIGURATION ====================
const config = {
  facebook: {
    api_key: "882a8490361da98702bf97a021ddc14d",
    secret: "62f8ce9f74b12f84c123cc23437a4a32"
  },
  security: {
    jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
    encryptionKey: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex')
  },
  rateLimits: {
    global: { windowMs: 60 * 1000, max: 100 },
    create: { windowMs: 60 * 1000, max: 10 },
    email: { windowMs: 60 * 1000, max: 30 }
  }
};

// ==================== CACHE SETUP ====================
const cache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });
const emailCache = new NodeCache({ stdTTL: 1800, checkperiod: 300 });

// ==================== MIDDLEWARE ====================
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-API-Secret']
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: config.rateLimits.global.windowMs,
  max: config.rateLimits.global.max,
  message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use('/api/', globalLimiter);

// ==================== AUTHENTICATION MIDDLEWARE ====================
const authenticateAPIKey = (requiredPermissions = []) => {
  return (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;
    const apiSecret = req.headers['x-api-secret'] || req.query.api_secret;

    if (!apiKey || !apiSecret) {
      return res.status(401).json({
        success: false,
        error: 'API key and secret are required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    try {
      const stmt = db.prepare('SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1');
      const keyData = stmt.get(apiKey);

      if (!keyData) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key',
          code: 'INVALID_KEY'
        });
      }

      // Verify secret
      const expectedSecret = keyData.api_secret;
      if (apiSecret !== expectedSecret) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API secret',
          code: 'INVALID_SECRET'
        });
      }

      // Check rate limit for this API key
      const rateLimitKey = `rate_${keyData.id}`;
      const requestCount = cache.get(rateLimitKey) || 0;
      if (requestCount >= keyData.rate_limit) {
        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded for this API key',
          code: 'RATE_LIMIT_EXCEEDED',
          limit: keyData.rate_limit
        });
      }
      cache.set(rateLimitKey, requestCount + 1, 60);

      // Check permissions
      const permissions = keyData.permissions.split(',');
      for (const perm of requiredPermissions) {
        if (!permissions.includes(perm)) {
          return res.status(403).json({
            success: false,
            error: `Missing required permission: ${perm}`,
            code: 'INSUFFICIENT_PERMISSIONS'
          });
        }
      }

      // Update last used
      db.prepare('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?').run(keyData.id);

      // Log activity
      db.prepare(`
        INSERT INTO activity_logs (api_key_id, action, ip, user_agent)
        VALUES (?, ?, ?, ?)
      `).run(keyData.id, req.method + ' ' + req.path, req.ip, req.headers['user-agent']);

      req.apiKey = keyData;
      next();
    } catch (error) {
      console.error('Auth error:', error);
      res.status(500).json({
        success: false,
        error: 'Authentication error',
        code: 'AUTH_ERROR'
      });
    }
  };
};

// ==================== UTILITY FUNCTIONS ====================
const utils = {
  encrypt(text) {
    const cipher = crypto.createCipher('aes-256-cbc', config.security.encryptionKey);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  },

  decrypt(encrypted) {
    const decipher = crypto.createDecipher('aes-256-cbc', config.security.encryptionKey);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  },

  generateAPIKey() {
    return 'fb_' + crypto.randomBytes(24).toString('hex');
  },

  generateAPISecret() {
    return 'sec_' + crypto.randomBytes(32).toString('hex');
  },

  generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex').substring(0, length);
  },

  generateRandomPassword(length = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < length; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  },

  getRandomDate(start = new Date(1976, 0, 1), end = new Date(2004, 0, 1)) {
    return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
  },

  filipinoFirstNames: [
    "Jake", "John", "Mark", "Michael", "Ryan", "Arvin", "Kevin", "Ian", "Carlo", "Jeffrey",
    "Joshua", "Bryan", "Jericho", "Christian", "Vincent", "Angelo", "Francis", "Patrick",
    "Maria", "Ana", "Lisa", "Jennifer", "Christine", "Catherine", "Jocelyn", "Marilyn"
  ],

  filipinoSurnames: [
    "Dela Cruz", "Santos", "Reyes", "Garcia", "Mendoza", "Flores", "Gonzales", "Lopez",
    "Cruz", "Perez", "Fernandez", "Villanueva", "Ramos", "Aquino", "Castro", "Rivera"
  ],

  getRandomName() {
    return {
      firstName: this.filipinoFirstNames[Math.floor(Math.random() * this.filipinoFirstNames.length)],
      lastName: this.filipinoSurnames[Math.floor(Math.random() * this.filipinoSurnames.length)]
    };
  },

  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  hashIP(ip) {
    return crypto.createHash('sha256').update(ip).digest('hex');
  }
};

// ==================== FACEBOOK CREATION FUNCTIONS ====================
const facebook = {
  async createAccount(options = {}) {
    try {
      const {
        firstName = utils.getRandomName().firstName,
        lastName = utils.getRandomName().lastName,
        email,
        password = utils.generateRandomPassword(12),
        gender = Math.random() < 0.5 ? "M" : "F",
        birthday = utils.getRandomDate()
      } = options;

      if (!email || !utils.validateEmail(email)) {
        throw new Error('Valid email is required');
      }

      const birthYear = birthday.getFullYear();
      const birthMonth = String(birthday.getMonth() + 1).padStart(2, '0');
      const birthDay = String(birthday.getDate()).padStart(2, '0');
      const formattedBirthday = `${birthYear}-${birthMonth}-${birthDay}`;

      const req = {
        api_key: config.facebook.api_key,
        attempt_login: true,
        birthday: formattedBirthday,
        client_country_code: "EN",
        fb_api_caller_class: "com.facebook.registration.protocol.RegisterAccountMethod",
        fb_api_req_friendly_name: "registerAccount",
        firstname: firstName,
        format: "json",
        gender: gender,
        lastname: lastName,
        email: email,
        locale: "en_US",
        method: "user.register",
        password: password,
        reg_instance: utils.generateRandomString(32),
        return_multiple_errors: true
      };

      const sigString = Object.keys(req)
        .sort()
        .map(key => `${key}=${req[key]}`)
        .join('') + config.facebook.secret;

      req.sig = crypto.createHash('md5').update(sigString).digest('hex');

      const response = await axios.post("https://b-api.facebook.com/method/user.register",
        new URLSearchParams(req), {
        headers: {
          "User-Agent": "[FBAN/FB4A;FBAV/35.0.0.48.273;FBDM/{density=1.33125,width=800,height=1205};FBLC/en_US;FBCR/;FBPN/com.facebook.katana;FBDV/Nexus 7;FBSV/4.1.1;FBBK/0;]",
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "*/*",
          "Accept-Language": "en-US",
          "Connection": "keep-alive"
        },
        timeout: 30000
      });

      if (response.data && !response.data.error) {
        const userId = response.data.new_user_id || response.data.uid || response.data.id || utils.generateRandomString(14);

        return {
          success: true,
          account: {
            email: email,
            password: password,
            firstName: firstName,
            lastName: lastName,
            birthday: formattedBirthday,
            userId: userId,
            profileLink: `https://facebook.com/profile.php?id=${userId}`,
            gender: gender,
            createdAt: new Date().toISOString()
          },
          raw: response.data
        };
      } else {
        return {
          success: false,
          error: response.data.error_msg || response.data.error || 'Registration failed'
        };
      }
    } catch (error) {
      console.error('Facebook creation error:', error.message);
      return {
        success: false,
        error: error.response?.data?.error_msg || error.message
      };
    }
  }
};

// ==================== API KEY MANAGEMENT ====================

// Create new API key (protected route for master key)
app.post('/api/admin/keys', authenticateAPIKey(['admin']), async (req, res) => {
  try {
    const { name, permissions = 'create,read', rate_limit = 100 } = req.body;

    const id = uuidv4();
    const apiKey = utils.generateAPIKey();
    const apiSecret = utils.generateAPISecret();

    const stmt = db.prepare(`
      INSERT INTO api_keys (id, api_key, api_secret, name, permissions, rate_limit)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(id, apiKey, apiSecret, name || 'API User', permissions, rate_limit);

    res.json({
      success: true,
      data: {
        id,
        api_key: apiKey,
        api_secret: apiSecret,
        name: name || 'API User',
        permissions,
        rate_limit
      }
    });
  } catch (error) {
    console.error('Error creating API key:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create API key'
    });
  }
});

// List all API keys (admin only)
app.get('/api/admin/keys', authenticateAPIKey(['admin']), (req, res) => {
  try {
    const stmt = db.prepare('SELECT id, api_key, name, permissions, rate_limit, created_at, last_used, is_active FROM api_keys');
    const keys = stmt.all();
    res.json({ success: true, data: keys });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch API keys' });
  }
});

// Revoke API key
app.delete('/api/admin/keys/:id', authenticateAPIKey(['admin']), (req, res) => {
  try {
    const stmt = db.prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?');
    stmt.run(req.params.id);
    res.json({ success: true, message: 'API key revoked successfully' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to revoke API key' });
  }
});

// ==================== ACCOUNT MANAGEMENT ENDPOINTS ====================

// Create Facebook account
app.post('/api/fbcreate', authenticateAPIKey(['create']), async (req, res) => {
  try {
    const { email, firstName, lastName, gender, password, autoGenerateEmail = false } = req.body;

    let finalEmail = email;

    if (autoGenerateEmail && !finalEmail) {
      const tempEmail = await generateTempEmail();
      finalEmail = tempEmail.email;
    }

    if (!finalEmail) {
      return res.status(400).json({
        success: false,
        error: 'Email is required or enable autoGenerateEmail',
        code: 'EMAIL_REQUIRED'
      });
    }

    if (!utils.validateEmail(finalEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format',
        code: 'INVALID_EMAIL'
      });
    }

    const result = await facebook.createAccount({
      email: finalEmail,
      firstName,
      lastName,
      gender,
      password
    });

    if (result.success) {
      const accountId = uuidv4();
      const stmt = db.prepare(`
        INSERT INTO accounts (id, user_id, email, password, first_name, last_name, birthday, gender, profile_link, api_key_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        accountId,
        result.account.userId,
        utils.encrypt(result.account.email),
        utils.encrypt(result.account.password),
        result.account.firstName,
        result.account.lastName,
        result.account.birthday,
        result.account.gender,
        result.account.profileLink,
        req.apiKey.id
      );

      // Don't send encrypted data to client
      result.account.email = finalEmail;
      result.account.password = password;

      return res.json({
        success: true,
        data: result.account,
        api_key_used: req.apiKey.name
      });
    } else {
      return res.status(400).json({
        success: false,
        error: result.error,
        code: 'CREATION_FAILED'
      });
    }
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

// Generate temporary email
async function generateTempEmail() {
  try {
    const response = await axios.post('https://api.internal.temp-mail.io/api/v3/email/new', {}, {
      timeout: 10000,
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }
    });
    return { email: response.data.email, fallback: false };
  } catch (error) {
    const randomStr = Math.random().toString(36).substring(2, 10);
    const domains = ['guerrillamail.com', 'temp-mail.org', '10minutemail.com'];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const email = `user_${randomStr}@${domain}`;
    return { email, fallback: true };
  }
}

app.get('/api/tempmail/gen', authenticateAPIKey(['create']), async (req, res) => {
  try {
    const result = await generateTempEmail();

    // Store in database
    const stmt = db.prepare('INSERT INTO temp_emails (email, api_key_id, expires_at) VALUES (?, ?, ?)');
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    stmt.run(result.email, req.apiKey.id, expiresAt.toISOString());

    res.json({
      success: true,
      data: {
        email: result.email,
        createdAt: new Date().toISOString(),
        expiresIn: '30 minutes',
        fallback: result.fallback
      }
    });
  } catch (error) {
    console.error('Email generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate email'
    });
  }
});

// Get accounts for current API key
app.get('/api/accounts', authenticateAPIKey(['read']), (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT id, user_id, email, first_name, last_name, birthday, gender, profile_link, created_at, status
      FROM accounts 
      WHERE api_key_id = ? 
      ORDER BY created_at DESC 
      LIMIT 100
    `);
    const accounts = stmt.all(req.apiKey.id);

    // Decrypt sensitive data
    accounts.forEach(acc => {
      if (acc.email) acc.email = utils.decrypt(acc.email);
    });

    res.json({
      success: true,
      data: accounts,
      count: accounts.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch accounts'
    });
  }
});

// Get single account by ID
app.get('/api/accounts/:id', authenticateAPIKey(['read']), (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT id, user_id, email, password, first_name, last_name, birthday, gender, profile_link, created_at, status
      FROM accounts 
      WHERE id = ? AND api_key_id = ?
    `);
    const account = stmt.get(req.params.id, req.apiKey.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'Account not found'
      });
    }

    // Decrypt sensitive data
    account.email = utils.decrypt(account.email);
    account.password = utils.decrypt(account.password);

    res.json({
      success: true,
      data: account
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch account'
    });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateAPIKey(['read']), (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN created_at > datetime('now', '-1 hour') THEN 1 ELSE 0 END) as last_hour,
        SUM(CASE WHEN created_at > datetime('now', '-1 day') THEN 1 ELSE 0 END) as last_day
      FROM accounts 
      WHERE api_key_id = ?
    `);
    const stats = stmt.get(req.apiKey.id);

    const logsStmt = db.prepare('SELECT COUNT(*) as total_requests FROM activity_logs WHERE api_key_id = ?');
    const logs = logsStmt.get(req.apiKey.id);

    res.json({
      success: true,
      data: {
        totalAccounts: stats.total || 0,
        lastHour: stats.last_hour || 0,
        lastDay: stats.last_day || 0,
        totalRequests: logs.total_requests || 0,
        apiKey: {
          name: req.apiKey.name,
          rateLimit: req.apiKey.rate_limit,
          permissions: req.apiKey.permissions
        },
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to fetch stats'
    });
  }
});

// Activity logs
app.get('/api/logs', authenticateAPIKey(['admin']), (req, res) => {
  try {
    const stmt = db.prepare(`
      SELECT l.*, k.name as api_key_name
      FROM activity_logs l
      LEFT JOIN api_keys k ON l.api_key_id = k.id
      ORDER BY l.created_at DESC
      LIMIT 100
    `);
    const logs = stmt.all();
    res.json({ success: true, data: logs });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch logs' });
  }
});

// Health check (public)
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'online',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'connected'
  });
});

// ==================== FRONTEND ROUTES ====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== INITIAL SETUP ====================
function setupInitialAPIKey() {
  const stmt = db.prepare('SELECT COUNT(*) as count FROM api_keys WHERE name = "Master Admin"');
  const result = stmt.get();

  if (result.count === 0) {
    const masterKey = utils.generateAPIKey();
    const masterSecret = utils.generateAPISecret();
    const id = uuidv4();

    db.prepare(`
      INSERT INTO api_keys (id, api_key, api_secret, name, permissions, rate_limit)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, masterKey, masterSecret, 'Master Admin', 'admin,create,read,delete', 1000);

    console.log('\n========================================');
    console.log('🔑 MASTER API KEY CREATED');
    console.log('========================================');
    console.log(`API Key: ${masterKey}`);
    console.log(`API Secret: ${masterSecret}`);
    console.log('========================================\n');
    console.log('⚠️  SAVE THESE CREDENTIALS SECURELY!');
    console.log('They will not be shown again.\n');

    // Save to file for reference
    const credFile = path.join(__dirname, 'master_credentials.txt');
    fs.writeFileSync(credFile, `API Key: ${masterKey}\nAPI Secret: ${masterSecret}\nCreated: ${new Date().toISOString()}`);
    console.log(`📁 Credentials saved to: ${credFile}\n`);
  }
}

// ==================== START SERVER ====================
setupInitialAPIKey();

app.listen(PORT, () => {
  console.log(`\n🚀 Facebook Account Creator API v2.0`);
  console.log(`========================================`);
  console.log(`📡 Server running on port ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`📁 Database: accounts.db`);
  console.log(`========================================\n`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing database and shutting down...');
  db.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing database and shutting down...');
  db.close();
  process.exit(0);
});

module.exports = app;