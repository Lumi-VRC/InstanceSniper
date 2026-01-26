// Instance Sniper - Detects and closes unauthorized instance creations
// Monitors groups for instance creation events and verifies creator permissions
// Created by @lumi_vrc [discord] to combat the exploit that allows users to open instances even if they lack the permissions to do so

const path = require("path"); // File path
const { VRChat, VRChatError } = require("vrchat"); // VRChat api library
const { KeyvFile } = require("keyv-file"); // Cookies for repeated login
const twofactor = require("node-2fa"); // 2FA login support
const mysql = require("mysql2/promise"); // Database support
const chalk = require("chalk"); // Pretty colored console :3

// Credentials.json stores our VRChat login as "config".
// Note: Use email instead of username. More stable.
// Username must be your original username; if you've name swapped, it doesn't change your login username.
const configPath = path.join(__dirname, "/config/credentials.json");
let config;
try {
    config = require(configPath);
} catch (err) {
    console.error(chalk.red.bold(`Missing VRChat config at ${configPath}. Please place credentials.json there.`));
    process.exit(1);
}

// mySQL Database login credentials, stored as "dbCfg", from "db.json".
const dbCfg = (() => {
    try { return require("/config/db.json"); } catch (e) { return {}; }
})();

const DB_HOST = dbCfg.host;
const DB_PORT = Number(dbCfg.port);
const DB_USER = dbCfg.user;
const DB_PASSWORD = dbCfg.password;
const DB_NAME = dbCfg.database;

// Rate limiting
// Generally, a given account can sustain 1 call per second, but slowing it down offers better stability.
// This program doesn't need to run at light speed.
const API_CALL_INTERVAL_MS = 5000; // 5 seconds between API calls
const GROUP_DELAY_MS = 5000; // 5 seconds delay after processing a group
const RATE_LIMIT_PAUSE_MS = 30 * 60 * 1000; // 30 minutes on 429

// Permission nodes to check.
const INSTANCE_CREATE_PERMISSIONS = [
    "group-instance-public-create",
    "group-instance-plus-create",
    "group-instance-open-create",
    "group-instance-restricted-create"
];

// VRChat SDK client
// This creates our VRChat login file + headers + cookie file.
// Fill out with your own "email", and change "name".
const loginEmail = config.VRChat.email;
const vrchat = new VRChat({
    baseUrl: "https://api.vrchat.cloud/api/1",
    application: {
        name: "instance-sniper",
        version: "1.0.0",
        contact: "example@example.com"
    },
    authentication: {
        credentials: {
            username: loginEmail,
            password: config.VRChat.pass,
            totpSecret: config.VRChat.twofa
        },
        optimistic: false
    },
    keyv: new KeyvFile({ filename: path.join(__dirname, "instance-sniper-cookies.json") })
});

// Set some variables to use later
let dbPool = null;
let lastApiCallTime = 0;
let rateLimitPausedUntil = 0;

// Generate 2FA TOTP token to use in login
function generateOtpToken() {
    const tokenObj = twofactor.generateToken(config.VRChat.twofa);
    if (!tokenObj || !tokenObj.token) {
        throw new Error("Failed to generate OTP token");
    }
    return tokenObj.token;
}

// Initialize database connection
async function initDatabase() {
    if (dbPool) return;
    dbPool = mysql.createPool({
        host: DB_HOST,
        port: DB_PORT,
        user: DB_USER,
        password: DB_PASSWORD,
        database: DB_NAME,
        connectionLimit: 10
    });
    console.log(chalk.blue("Database connection pool created"));
}

// Create exploitDB table if it doesn't exist, taking responsibility away from end user.
// Indexed by Group ID
async function ensureTable() {
    await initDatabase();
    const sql = `
        CREATE TABLE IF NOT EXISTS exploitDB (
            id INT AUTO_INCREMENT PRIMARY KEY,
            groupId VARCHAR(255) NOT NULL UNIQUE,
            actorIds JSON NOT NULL,
            auditLogIds JSON NOT NULL,
            instanceIds JSON NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_groupId (groupId)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `;
    await dbPool.query(sql);
    console.log(chalk.blue("Table exploitDB ensured"));
}

// Function definition
// Get existing data for a group (single row per group)
// We only maintain one row per group, so no need to search for duplicate group Ids.
async function getGroupData(groupId) {
    await initDatabase(); // Ensure the database is initialized before beginning
    const [rows] = await dbPool.query( // Pull data
        "SELECT actorIds, auditLogIds, instanceIds FROM exploitDB WHERE groupId = ? LIMIT 1",
        [groupId]
    );
    if (rows.length === 0) { // Patch: Empty database handler
        return { actorIds: [], auditLogIds: [], instanceIds: [] };
    }
    
    const row = rows[0];
    // Patch: Handle null/undefined JSON columns. Would not stop crashing without this.
    const actorIds = row.actorIds ? (typeof row.actorIds === 'string' ? JSON.parse(row.actorIds) : row.actorIds) : [];
    const logIds = row.auditLogIds ? (typeof row.auditLogIds === 'string' ? JSON.parse(row.auditLogIds) : row.auditLogIds) : [];
    const instanceIds = row.instanceIds ? (typeof row.instanceIds === 'string' ? JSON.parse(row.instanceIds) : row.instanceIds) : [];
    
    return { // Return arrays of data.
        actorIds: Array.isArray(actorIds) ? actorIds : [],
        auditLogIds: Array.isArray(logIds) ? logIds : [],
        instanceIds: Array.isArray(instanceIds) ? instanceIds : []
    };
}


// Function definition
// Update or insert group data (appends to existing arrays, one row per group)
async function updateOrInsertGroupData(groupId, newActorIds, newAuditLogIds, newInstanceIds) {
    await initDatabase();
    // Ensure arrays are not null/undefined
    const safeNewActorIds = Array.isArray(newActorIds) ? newActorIds : [];
    const safeNewLogIds = Array.isArray(newAuditLogIds) ? newAuditLogIds : [];
    const safeNewInstanceIds = Array.isArray(newInstanceIds) ? newInstanceIds : [];
    
    // Get existing data for this group
    const existingData = await getGroupData(groupId);
    
    // Merge new data with existing (avoid duplicates)
    const mergedActorIds = Array.from(new Set([...existingData.actorIds, ...safeNewActorIds]));
    const mergedLogIds = Array.from(new Set([...existingData.auditLogIds, ...safeNewLogIds]));
    const mergedInstanceIds = Array.from(new Set([...existingData.instanceIds, ...safeNewInstanceIds]));
    
    // Check if row exists
    const [rows] = await dbPool.query(
        "SELECT id FROM exploitDB WHERE groupId = ? LIMIT 1",
        [groupId]
    );
    
    if (rows.length > 0) {
        // Update existing row
        const sql = `
            UPDATE exploitDB 
            SET actorIds = ?, auditLogIds = ?, instanceIds = ?
            WHERE groupId = ?
        `;
        await dbPool.query(sql, [ 
            JSON.stringify(mergedActorIds),
            JSON.stringify(mergedLogIds),
            JSON.stringify(mergedInstanceIds),
            groupId
        ]);
    } else {
        // Insert new row
        const sql = `
            INSERT INTO exploitDB (groupId, actorIds, auditLogIds, instanceIds)
            VALUES (?, ?, ?, ?)
        `;
        await dbPool.query(sql, [
            groupId,
            JSON.stringify(mergedActorIds),
            JSON.stringify(mergedLogIds),
            JSON.stringify(mergedInstanceIds)
        ]);
    }
}

// Function definition
// Get all unique group IDs from the database
// This is called at the start of each loop to create a list of groups to iterate through.
async function getAllGroupIds() {
    await initDatabase();
    const [rows] = await dbPool.query(
        "SELECT DISTINCT groupId FROM exploitDB ORDER BY groupId"
    );
    return rows.map(row => row.groupId);
}

// Function definition
// Insert group IDs into database from command-line arguments
// Usage: "node instanceSniper.js grp_xxxxx"
async function insertGroupIds(groupIds) {
    if (!groupIds || groupIds.length === 0) {
        return;
    }
    
    await initDatabase();
    
    for (const groupId of groupIds) {
        // Trim whitespace and validate format
        const trimmedId = groupId.trim();
        if (!trimmedId || !trimmedId.startsWith('grp_')) {
            console.log(chalk.yellow(`Skipping invalid group ID: ${chalk.gray(trimmedId)}`));
            continue;
        }
        
        try {
            // Use INSERT IGNORE to safely insert (won't error if already exists)
            const [result] = await dbPool.query(
                "INSERT IGNORE INTO exploitDB (groupId, actorIds, auditLogIds, instanceIds) VALUES (?, '[]', '[]', '[]')",
                [trimmedId]
            );
            if (result.affectedRows > 0) { // Success
                console.log(chalk.green(`Inserted group ID: ${chalk.cyan(trimmedId)}`));
            } else { // Already exists, failure
                console.log(chalk.gray(`Group ID already exists: ${chalk.cyan(trimmedId)}`));
            }
        } catch (err) { // Failure, error
            console.error(chalk.red(`Failed to insert group ID ${chalk.cyan(trimmedId)}:`), chalk.red(err.message || err));
        }
    }
}

// Function definition
// Rate limiter helper - ensures 1 API call per 5 seconds
async function rateLimit() {
    const now = Date.now();
    
    // Check if we're paused due to rate limiting
    if (now < rateLimitPausedUntil) {
        const waitTime = rateLimitPausedUntil - now;
        console.log(chalk.yellow.bold(`Rate limit pause active. Waiting ${chalk.white(Math.ceil(waitTime / 1000))} seconds...`));
        await sleep(waitTime);
        return;
    }
    
    // Check if we need to wait for the interval
    const timeSinceLastCall = now - lastApiCallTime;
    if (timeSinceLastCall < API_CALL_INTERVAL_MS) {
        const waitTime = API_CALL_INTERVAL_MS - timeSinceLastCall;
        console.log(chalk.yellow(`  Rate limiting: waiting ${chalk.white((waitTime / 1000).toFixed(1))} seconds before API call...`));
        await sleep(waitTime);
    }
}

// Function definition
// Sleep helper for rate limiting
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Function definition
// Login to VRChat using cookies, then fallback to 2fa login
async function login() {
    console.log(chalk.cyan.bold("Starting login flow..."));
    try {
        // Try cookie reuse first
        const cookieCount = (await vrchat.getCookies())?.length || 0;
        console.log(chalk.gray(`  Cookie count before auth: ${chalk.white(cookieCount)}`));
        
        if (cookieCount > 0) {
            await rateLimit();
            const resp = await vrchat.getCurrentUser({ throwOnError: true, meta: {} });
            if (resp?.data?.displayName) {
                console.log(chalk.green(`Session reuse: logged in via stored cookies as: ${chalk.cyan(resp.data.displayName)}`));
                return resp.data;
            }
        }
        
        // Fresh credential + TOTP login
        console.log(chalk.yellow("  Performing credential login..."));
        const otpCode = generateOtpToken();
        await rateLimit();
        await vrchat.login({
            username: loginEmail,
            password: config.VRChat.pass,
            twoFactorCode: () => otpCode,
            throwOnError: true,
            meta: {}
        });
        
        await rateLimit();
        const resp = await vrchat.getCurrentUser({ throwOnError: true, meta: {} });
        console.log(chalk.green(`Logged in as: ${chalk.cyan(resp.data.displayName)}`));
        return resp.data;
    } catch (err) {
        const message = err instanceof VRChatError
            ? `VRChatError ${err.statusCode}: ${err.message}`
            : (err && err.message) || String(err);
        console.error(chalk.red.bold(`Login attempt failed: ${chalk.white(message)}`));
        process.exit(1);
    }
}

// Function Definition
// Make API call with rate limiting and 429 handling
async function makeApiCall(apiCallFn) {
    await rateLimit();
    
    try {
        const result = await apiCallFn();
        // Update last API call time AFTER the call completes
        lastApiCallTime = Date.now();
        return result;
    } catch (err) {
        // Update last API call time even on error (to prevent rapid retries)
        lastApiCallTime = Date.now();
        
        if (err instanceof VRChatError && err.statusCode === 429) {
            console.log(chalk.red.bold("Received 429 rate limit. Pausing for 30 minutes..."));
            rateLimitPausedUntil = Date.now() + RATE_LIMIT_PAUSE_MS;
            // Wait and retry
            await sleep(RATE_LIMIT_PAUSE_MS);
            return makeApiCall(apiCallFn);
        }
        throw err; // :(
    }
}

// Function definition
// Parse targetId to extract worldId and instanceId
function parseInstanceLocation(targetId) {
    if (!targetId || typeof targetId !== "string") {
        return null;
    }
    
    // Format: "wrld_4432ea9b-729c-46e3-8eaf-846aa0a37fdd:12345~group(grp_xxx)~groupAccessType(public)~region(eu)"
    // For closing instances, we need worldId and the instance part (everything after the colon, including flags for some reason)
    const colonIndex = targetId.indexOf(':');
    if (colonIndex === -1) {
        return null;
    }
    
    const worldId = targetId.substring(0, colonIndex);
    // Use everything after the colon as instanceId (includes flags which may be needed)
    const instanceId = targetId.substring(colonIndex + 1);
    
    return {
        worldId, // wrld_xxx...
        instanceId // 12345~flag(data)~flag(data)...
    };
}

// Function definition
// VRC API
// Get group audit logs
async function getGroupAuditLogs(groupId) {
    // Rate limiting happens inside makeApiCall, but we log before to show intent
    return makeApiCall(() => {
        console.log(chalk.magenta(`  Calling API: ${chalk.cyan("getGroupAuditLogs")}\n`));
        return vrchat.getGroupAuditLogs({
            path: { groupId },
            throwOnError: true,
            meta: {}
        });
    });
}

// Function definition
// VRC API
// Get group roles
async function getGroupRoles(groupId) {
    // Rate limiting happens inside makeApiCall, but we log before to show intent
    return makeApiCall(() => {
        console.log(chalk.magenta(`  Calling API: ${chalk.cyan("getGroupRoles")}\n`));
        return vrchat.getGroupRoles({
            path: { groupId },
            throwOnError: true,
            meta: {}
        });
    });
}

// Function definition
// VRC API
// Get group member
async function getGroupMember(groupId, userId) {
    return makeApiCall(() => {
        console.log(chalk.magenta(`    Calling API: getGroupMember\n`));
        return vrchat.getGroupMember({
            path: { groupId, userId },
            throwOnError: false, // Don't throw on error, return error response instead
            meta: {}
        });
    });
}

// Function definition
// VRC API
// Close instance
async function closeInstance(worldId, instanceId) {
    // The API endpoint is DELETE /instances/{worldId}:{instanceId}
    // Based on testing, the SDK requires the FULL instance string with flags, not just the instance ID
    // Use the full instanceId (with flags) for the API call
    console.log(chalk.magenta(`    CloseInstance call - WorldId: ${chalk.cyan(worldId)}, InstanceId (full): ${chalk.cyan(instanceId)}\n`));
    
    // The SDK expects separate worldId and instanceId parameters
    // instanceId must include the full string with flags: "676727~group(...)~groupAccessType(...)~region(...)"
    return makeApiCall(() => vrchat.closeInstance({
        path: { worldId, instanceId },
        throwOnError: true,
        meta: {}
    }));
}

// Function definition
// Cross references roles & their permissions VS user and their roles
// Check if user has instance creation permissions listed at start of file
function hasInstanceCreatePermission(userRoleIds, rolePermissionsMap) {
    for (const roleId of userRoleIds) {
        const permissions = rolePermissionsMap[roleId] || [];
        for (const perm of permissions) {
            // Check for wildcard permission first
            if (perm === "*") {
                return true;
            }
            // Check for specific instance creation permissions
            if (INSTANCE_CREATE_PERMISSIONS.includes(perm)) {
                return true;
            }
        }
    }
    return false;
}

// Function definition
// Process a single group
// The majority of the logic is here!
// 1. [API] Fetches audit logs.
// 2. Filters for instance creation events, deduplicates against ones already checked.
// 3. If any exist, continue. Otherwise, exit loop and proceed to next group.
// 4. [API] Obtain group roles and build a map attributing roles -> permissions.
// 5. Enumerate each instance creation event, and handle them sequentially.
// 6. [API] Obtain roles set on user: instance creator.
// 7. Cross reference against map of role attributions, checking to see if they have instance creation permissions.
// 8. If valid, record logID to avoid duplicate checks, and proceed.
// 9. If invalid, record logID, location, and actorID, then attempt to close instance.
// 10. Input recorded data from each event into database, then proceed to next group id.
async function processGroup(groupId) {
    console.log(chalk.blue.bold(`\nProcessing group: ${chalk.cyan(groupId)}`));
    
    try {
        // Get existing data for deduplication by audit log ID
        const existingData = await getGroupData(groupId);
        const existingLogIds = new Set(existingData.auditLogIds);
        
        // Fetch audit logs
        console.log(chalk.cyan.bold(`----- Checking for new instances -----`));
        const auditLogsResp = await getGroupAuditLogs(groupId);
        console.log(chalk.green(`  Audit logs fetched (${chalk.white(auditLogsResp?.data?.results?.length || auditLogsResp?.data?.data?.length || auditLogsResp?.data?.length || 0)} entries)\n`));
        // Handle different response structures (results, data, or direct array)
        // Self-note: Confirm data structure and clean this later. I couldn't remember which it was, was too tired to care.
        let auditLogs = [];
        if (auditLogsResp?.data) {
            if (Array.isArray(auditLogsResp.data.results)) {
                auditLogs = auditLogsResp.data.results;
            } else if (Array.isArray(auditLogsResp.data.data)) {
                auditLogs = auditLogsResp.data.data;
            } else if (Array.isArray(auditLogsResp.data)) {
                auditLogs = auditLogsResp.data;
            }
        }
        
        // Filter for instance creation events
        const instanceCreateLogs = auditLogs.filter(log => {
            const eventType = (log.eventType || "").toLowerCase();
            return eventType === "group.instance.create";
        });
        
        // Filter out already processed logs by log ID
        const newLogs = instanceCreateLogs.filter(log => !existingLogIds.has(log.id));
        
        if (newLogs.length === 0) { // deeeeaddd groooooouuupppp
            console.log(chalk.gray(`  No new instance creation events found`));
            return;
        }
        
        // Only fetch group roles if we have new instance creation events to process using return above; Lightens load on API
        console.log(chalk.cyan.bold(`-- Syncing roles in memory --`));
        const rolesResp = await getGroupRoles(groupId); // VRCAPI call
        console.log(chalk.green(`  Group roles fetched (${chalk.white(rolesResp?.data?.results?.length || rolesResp?.data?.data?.length || rolesResp?.data?.length || 0)} roles)\n`));
        // Handle different response structures
        let roles = [];
        if (rolesResp?.data) {
            if (Array.isArray(rolesResp.data.results)) {
                roles = rolesResp.data.results;
            } else if (Array.isArray(rolesResp.data.data)) {
                roles = rolesResp.data.data;
            } else if (Array.isArray(rolesResp.data)) {
                roles = rolesResp.data;
            }
        }
        
        // Build role-permissions attribution map
        const rolePermissionsMap = {};
        for (const role of roles) {
            if (role.id && role.permissions) {
                rolePermissionsMap[role.id] = role.permissions;
            }
        }
        
        console.log(chalk.cyan.bold(`-- Instance discovery --`));
        console.log(chalk.yellow.bold(`  Found ${chalk.white(newLogs.length)} new instance creation event(s)`));
        console.log(chalk.cyan.bold(`-- ${chalk.white(newLogs.length)} instances discovered --\n`));
        
        // Process each log sequentially in case of multiple logs discovered in one pull, enumerating them.
        const newActorIds = [];
        const newLogIds = [];
        const newInstanceIds = [];

        // Begin processing
        for (let i = 0; i < newLogs.length; i++) {
            const log = newLogs[i];
            const instanceNumber = i + 1;
            const actorId = log.actorId;
            const logId = log.id;
            
            // Parse instance location once and reuse
            let instancePair = null;
            let location = null;
            const targetId = log.targetId;
            if (targetId) {
                location = parseInstanceLocation(targetId);
                if (location && location.worldId && location.instanceId) {
                    instancePair = `${location.worldId}:${location.instanceId}`;
                    // Always log instance ID for debugging..
                    newInstanceIds.push(instancePair);
                }
            }
            
            if (!actorId) {
                console.log(chalk.yellow(`    Instance ${instanceNumber}: No actorId found in log, skipping permission check`));
                continue;
            }
            
            // Always add log ID to processed list
            newLogIds.push(logId);
            
            try {
                // Get group member to check roles
                console.log(chalk.cyan.bold(`-- Checking instance ${chalk.white(instanceNumber)} creator --`));
                let memberResp;
                try {
                    memberResp = await getGroupMember(groupId, actorId);
                } catch (sdkErr) {
                    console.log(""); // Newline after API call
                    // Handle SDK errors (including internal null reference errors)
                    // The SDK may throw errors during response parsing
                    const errorMsg = sdkErr?.message || String(sdkErr);
                    const statusCode = sdkErr?.statusCode || sdkErr?.status_code || sdkErr?.response?.status;
                    
                    // Check if it's a 404 or if the error suggests the user is not a member
                    if (statusCode === 404 || errorMsg.includes('not found') || errorMsg.includes('Cannot read properties of null')) {
                        console.log(chalk.cyan.bold(`-- Instance ${chalk.white(instanceNumber)} Disallowed --`));
                        if (instancePair) {
                            console.log(chalk.red(`  Location: ${chalk.cyan(instancePair)}`));
                        }
                        console.log(chalk.yellow.bold(`  User ${chalk.cyan(actorId)} is not a member or data unavailable. Treating as unauthorized.`));
                        // Treat as unauthorized - user created instance but is no longer a member or data is corrupted
                        if (!newActorIds.includes(actorId)) {
                            newActorIds.push(actorId);
                        }
                        // Attempt to close instance
                        if (location && instancePair) {
                            console.log(chalk.magenta(`    Attempting to close instance: ${chalk.cyan(instancePair)}`));
                            try {
                                await closeInstance(location.worldId, location.instanceId);
                                console.log(chalk.green.bold(`    Successfully closed instance ${chalk.cyan(instancePair)}\n`));
                            } catch (closeErr) {
                                if (closeErr instanceof VRChatError && closeErr.statusCode === 403 && closeErr.message?.includes('already closed')) {
                                    console.log(chalk.green(`    Instance already closed (format was correct)\n`));
                                } else {
                                    console.error(chalk.red(`    Failed to close instance ${chalk.cyan(instancePair)}:`), chalk.red(closeErr.message || closeErr));
                                    console.error(chalk.red(`    WorldId: ${chalk.cyan(location.worldId)}, InstanceId: ${chalk.cyan(location.instanceId)}\n`));
                                }
                            }
                        } else {
                            console.log(""); // Newline if no instance to close
                        }
                    } else {
                        console.error(chalk.red(`    Error fetching member ${chalk.cyan(actorId)}:`), chalk.red(errorMsg));
                    }
                    continue;
                }
                
                // Check for error response (when throwOnError is false)
                // Nested if statements probably wasn't the best option. . .
                if (memberResp?.error) {
                    const error = memberResp.error;
                    if (error.status_code === 404) {
                        console.log(chalk.cyan.bold(`-- Instance ${chalk.white(instanceNumber)} Disallowed --`));
                        if (instancePair) {
                            console.log(chalk.red(`  Location: ${chalk.cyan(instancePair)}`));
                        }
                        console.log(chalk.yellow.bold(`  User ${chalk.cyan(actorId)} is not a member of the group (404). Treating as unauthorized.`));
                        // Treat as unauthorized
                        if (!newActorIds.includes(actorId)) {
                            newActorIds.push(actorId);
                        }
                        // Attempt to close instance
                        if (location && instancePair) {
                            console.log(chalk.magenta(`    Attempting to close instance: ${chalk.cyan(instancePair)}`));
                            try {
                                await closeInstance(location.worldId, location.instanceId);
                                console.log(chalk.green.bold(`    Successfully closed instance ${chalk.cyan(instancePair)}\n`));
                            } catch (closeErr) {
                                if (closeErr instanceof VRChatError && closeErr.statusCode === 403 && closeErr.message?.includes('already closed')) {
                                    console.log(chalk.green(`    Instance already closed (format was correct)\n`));
                                } else {
                                    console.error(chalk.red(`    Failed to close instance ${chalk.cyan(instancePair)}:`), chalk.red(closeErr.message || closeErr));
                                    console.error(chalk.red(`    WorldId: ${chalk.cyan(location.worldId)}, InstanceId: ${chalk.cyan(location.instanceId)}\n`));
                                }
                            }
                        } else {
                            console.log(""); // Newline if no instance to close
                        }
                    } else {
                        console.error(chalk.red(`    API error fetching member ${chalk.cyan(actorId)}: ${chalk.white(error.status_code)} - ${chalk.white(error.message)}\n`));
                    }
                    continue;
                }
                
                const member = memberResp?.data;
                console.log(""); // Newline after API call :3
                
                if (!member) {
                    console.log(chalk.yellow(`    Could not fetch member data (null response)\n`));
                    continue;
                }
                
                // Get user's role IDs
                const userRoleIds = [
                    ...(member.roleIds || []),
                    ...(member.mRoleIds || [])
                ];
                
                // Check if user has permission
                const hasPermission = hasInstanceCreatePermission(userRoleIds, rolePermissionsMap);
                
                if (hasPermission) {
                    console.log(chalk.cyan.bold(`-- Instance ${chalk.white(instanceNumber)} Allowed --`));
                    if (instancePair) {
                        console.log(chalk.green(`  Location: ${chalk.cyan(instancePair)}`));
                    }
                    console.log(chalk.green(`  User ${chalk.cyan(actorId)} HAS permission to create instances. Logging log ID and instance ID only.\n`));
                    // Don't add actorId, but keep log ID and instance ID
                } else {
                    console.log(chalk.cyan.bold(`-- Instance ${chalk.white(instanceNumber)} Disallowed --`));
                    if (instancePair) {
                        console.log(chalk.red(`  Location: ${chalk.cyan(instancePair)}`));
                    }
                    console.log(chalk.red.bold(`  User ${chalk.cyan(actorId)} DOES NOT have permission! Logging actorId and attempting to close instance.`));
                    
                    // Add actorId to list
                    if (!newActorIds.includes(actorId)) {
                        newActorIds.push(actorId);
                    }
                    
                    // Attempt to close instance if we have the location
                    if (location && instancePair) {
                        console.log(chalk.magenta(`    Attempting to close instance: ${chalk.cyan(instancePair)}`));
                        try {
                            await closeInstance(location.worldId, location.instanceId);
                            console.log(chalk.green.bold(`    Successfully closed instance ${chalk.cyan(instancePair)}\n`));
                        } catch (closeErr) {
                            if (closeErr instanceof VRChatError && closeErr.statusCode === 403 && closeErr.message?.includes('already closed')) {
                                console.log(chalk.green(`    Instance already closed (format was correct)\n`));
                            } else {
                                console.error(chalk.red(`    Failed to close instance ${chalk.cyan(instancePair)}:`), chalk.red(closeErr.message || closeErr));
                                console.error(chalk.red(`    WorldId: ${chalk.cyan(location.worldId)}, InstanceId (full): ${chalk.cyan(location.instanceId)}\n`));
                            }
                        }
                    } else {
                        console.log(chalk.yellow(`    Cannot close instance - location not available\n`));
                    }
                }
            } catch (memberErr) {
                // Catch any other unexpected errors
                console.error(chalk.red.bold(`    Unexpected error checking member ${chalk.cyan(actorId)}:`), chalk.red(memberErr.message || memberErr));
                if (memberErr.stack) {
                    console.error(chalk.red(`    Stack:`), chalk.gray(memberErr.stack));
                }
                console.log(""); // Newline after error
                // Continue to next log even if this one fails
            }
        }
        
        // Update database with new data (appends to existing arrays)
        if (newLogIds.length > 0) {
            console.log(chalk.cyan.bold(`-- Logging data to mySQL table --`));
            await updateOrInsertGroupData(groupId, newActorIds, newLogIds, newInstanceIds);
            console.log(chalk.green(`  Updated database for group ${chalk.cyan(groupId)}: added ${chalk.white(newLogIds.length)} log(s), ${chalk.white(newActorIds.length)} actor(s), ${chalk.white(newInstanceIds.length)} instance(s)\n`));
        } else {
            console.log(chalk.gray(`  No new data to update for group ${chalk.cyan(groupId)}`));
        }
        
    } catch (err) {
        console.error(chalk.red.bold(`  Error processing group ${chalk.cyan(groupId)}:`), chalk.red(err.message || err));
        throw err;
    }
}

// Main execution
async function main() {
    console.log(chalk.cyan.bold("Instance Sniper starting...\n"));
    
    // Parse command-line arguments (group IDs)
    const cmdLineGroupIds = process.argv.slice(2).filter(arg => arg.trim().length > 0);
    
    try {
        // Initialize database and table
        await initDatabase();
        await ensureTable();
        
        // Insert group IDs from command-line arguments if provided
        if (cmdLineGroupIds.length > 0) {
            console.log(chalk.blue(`\nInserting ${chalk.white(cmdLineGroupIds.length)} group ID(s) from command-line arguments...`));
            await insertGroupIds(cmdLineGroupIds);
            console.log("");
        }
        
        // Login
        await login();
        
        // Main processing loop
        while (true) { // weeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
            // Get all group IDs from database
            const groupIds = await getAllGroupIds();
            
            if (groupIds.length === 0) {
                console.log(chalk.yellow("No group IDs found in database. Checking again in 5 seconds..."));
                await sleep(5000);
                continue;
            }
            
            console.log(chalk.blue.bold(`\nFound ${chalk.white(groupIds.length)} group(s) in database:`));
            groupIds.forEach(gid => console.log(chalk.cyan(`  - ${gid}`)));
            
            // Process each group
            for (let i = 0; i < groupIds.length; i++) {
                const groupId = groupIds[i];
                
                try {
                    await processGroup(groupId);
                } catch (err) {
                    console.error(chalk.red.bold(`Failed to process group ${chalk.cyan(groupId)}:`), chalk.red(err.message || err));
                    // Continue to next group
                }
                
                // Delay between groups (except after the last one)
                if (i < groupIds.length - 1) {
                    console.log(chalk.gray(`\nWaiting ${chalk.white(GROUP_DELAY_MS / 1000)} seconds before next group...`));
                    await sleep(GROUP_DELAY_MS);
                }
            }
            
            // After processing all groups, wait before checking again
            console.log(chalk.green("\nCompleted processing all groups. Checking for new groups in 5 seconds..."));
            await sleep(5000);
        }
        
    } catch (err) {
        console.error(chalk.red.bold("Fatal error:"), chalk.red(err));
        process.exit(1);
    }
}

// Run if executed directly instead of being imported and used externally
if (require.main === module) {
    main().catch(err => {
        console.error(chalk.red.bold("Unhandled error:"), chalk.red(err));
        process.exit(1);
    });
}

// Export heavy lifting functions for use externally
module.exports = {
    login,
    processGroup,
    makeApiCall,
    parseInstanceLocation
};
