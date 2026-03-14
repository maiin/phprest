<?php
/**
 * PHABLE CORE API - v0.1
 * architecture: "Frozen Core with Plugin Bridge"
 * security: "Stateless JWT Auth"
 * tools: "Integrated /stresstest UI"
 */

// Error reporting for debugging (Disable in production)
ini_set('display_errors', 0); 
error_reporting(E_ALL);

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') exit;

$configFile = __DIR__ . '/config.php';
$pluginFile = __DIR__ . '/plugins.php';
$secret = getenv('SECRET_CODE') ?: null;
if (!$secret) api(['error' => 'Server misconfiguration'], 500);

function createSlug($str) { return strtolower(trim(preg_replace('/[^A-Za-z0-9-]+/', '-', $str), '-')); }
function api($data, $code = 200) { http_response_code($code); echo json_encode($data, JSON_PRETTY_PRINT); exit; }

// --- JWT ENGINE ---
function jwt_encode($payload, $secret) {
    $h = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode(['typ'=>'JWT','alg'=>'HS256'])));
    $p = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($payload)));
    $s = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(hash_hmac('sha256', "$h.$p", $secret, true)));
    return "$h.$p.$s";
}

function jwt_decode($t, $secret) {
    if(!$t) return null;
    $p = explode('.', $t); if(count($p) != 3) return null;
    $s = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(hash_hmac('sha256', "$p[0].$p[1]", $secret, true)));
    return ($s === $p[2]) ? json_decode(base64_decode($p[1]), true) : null;
}

// --- AUTH ORCHESTRATOR with ULTRA DEBUG ---
$headers = getallheaders();

// DEBUG: Dump all received headers to error log
error_log("=== ALL HEADERS RECEIVED ===");
foreach ($headers as $key => $value) {
    error_log("$key: $value");
}

$auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$token = str_replace('Bearer ', '', $auth);

// DEBUG: What did we get?
error_log("Auth header raw: " . ($auth ?: 'MISSING'));
error_log("Token after strip: " . ($token ?: 'MISSING'));

$jwt = jwt_decode($token, $secret);

// DEBUG: JWT decode result
if ($token && !$jwt) {
    error_log("JWT DECODE FAILED for token: " . substr($token, 0, 20) . "...");
    // Check token format
    $parts = explode('.', $token);
    error_log("Token parts count: " . count($parts));
    if (count($parts) == 3) {
        // Try to decode just the payload to see if it's valid JSON
        $payload = base64_decode(strtr($parts[1], '-_', '+/'));
        error_log("Payload base64: " . $payload);
    }
} else if ($jwt) {
    error_log("JWT DECODE SUCCESS: uid=" . ($jwt['uid'] ?? 'none') . ", role=" . ($jwt['role'] ?? 'none'));
}

$uID = $jwt['uid'] ?? null;
$role = $jwt['role'] ?? 0;
$isAdmin = ($role >= 3);

error_log("Final role set to: " . $role);

function check_rights($matrix, $user_role) {
    $m = $_SERVER['REQUEST_METHOD'];
    $map = ['GET'=>0, 'POST'=>1, 'PATCH'=>2, 'DELETE'=>3];
    $idx = $map[$m] ?? 0;
    $req = $matrix[$idx] ?? 3;
    if ($user_role < $req) api(['error'=>'Forbidden', 'req'=>$req, 'lvl'=>$user_role], 403);
}

// --- DB INITIALIZATION ---
if (!file_exists($configFile)) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        try {
            $h=$_POST['db_h']; $n=$_POST['db_n']; $u=$_POST['db_u']; $p=$_POST['db_p'];
            $db = new PDO("mysql:host=$h", $u, $p, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $db->exec("CREATE DATABASE IF NOT EXISTS `$n`; USE `$n`;");
            $db->exec("CREATE TABLE IF NOT EXISTS ph_users (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) UNIQUE, password VARCHAR(255), role TINYINT DEFAULT 1);");
            $db->exec("CREATE TABLE IF NOT EXISTS ph_phables (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, pageslug VARCHAR(255) UNIQUE, type VARCHAR(50), belongsto VARCHAR(50), is_published TINYINT(1) DEFAULT 0, data JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);");
            $db->exec("CREATE TABLE IF NOT EXISTS ph_blocks (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, pageslug VARCHAR(255) UNIQUE, type VARCHAR(50), belongsto VARCHAR(50), is_published TINYINT(1) DEFAULT 0, data JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);");
            $db->prepare("INSERT IGNORE INTO ph_users (email, password, role) VALUES (?, ?, 3)")->execute([$_POST['admin_e'], password_hash($_POST['admin_p'], PASSWORD_DEFAULT)]);
            file_put_contents($configFile, "<?php\n\$db_host='$h';\n\$db_name='$n';\n\$db_user='$u';\n\$db_pass='$p';");
            api(['status' => 'Installed']);
        } catch (Exception $e) { api(['error' => $e->getMessage()], 500); }
    }
    header('Content-Type: text/html');
    echo "<h3>Phable v2.6.2 Installer</h3><form method='POST'><input name='db_h' value='localhost'><input name='db_n' placeholder='DB Name'><input name='db_u' placeholder='DB User'><input name='db_p' type='password' placeholder='DB Pass'><hr><input name='admin_e' placeholder='Admin Email'><input name='admin_p' placeholder='Admin Pass'><button>Install</button></form>";
    exit;
}

require $configFile;
try { 
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]); 
} catch (PDOException $e) { api(['error' => 'DB Fail'], 500); }

// --- ROUTING ---
$uri = str_replace([str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), 'index.php'], '', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$parts = explode('/', trim($uri, '/'));
$res = $parts[0] ?: 'info'; 
$id = $parts[1] ?? null;
$subId = $parts[2] ?? null; // Add this to capture the actual ID/Slug
$in = json_decode(file_get_contents('php://input'), true);



// --- COLLECTION HANDLER FUNCTION ---
// Full CRUD handler for any standard-schema table.
// Called by switch cases and by plugins via handle_plugins().
// See the 'phable' and 'blocks' cases below for usage examples.
function collection_handler($table, $rights, $pdo, $id, $subId, $in, $uID, $role) {
    // Every collection table is expected to have these standard columns:
    //   id, user_id, pageslug, type, belongsto, is_published, data (JSON), created_at
    //
    // `belongsto` is not optional — it gives every record context: which parent,
    // page, or container it belongs to. It can be a numeric ID, a slug string,
    // or left null for top-level records. This is what makes /children/:id work
    // universally across all collections without any extra configuration.
    check_rights($rights, $role);
    $method = $_SERVER['REQUEST_METHOD'];

    if ($method === 'GET') {
        $pubClause = ($role >= 2) ? "1=1" : "is_published=1";
        $typeFilter  = isset($_GET['type']) ? trim($_GET['type']) : null;
        $searchQuery = isset($_GET['q'])    ? trim($_GET['q'])    : null;
        $rows = [];

        if ($id === 'children' && $subId) {
            // GET /{collection}/children/:id — fetch child records by parent ID or slug
            if (!is_numeric($subId)) {
                $p = $pdo->prepare("SELECT id FROM $table WHERE pageslug = ? LIMIT 1");
                $p->execute([$subId]);
                $pRow = $p->fetch();
                $lookupId = $pRow['id'] ?? 0;
            } else {
                $lookupId = $subId;
            }
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE belongsto = ? AND $pubClause");
            $stmt->execute([$lookupId]);
            $rows = $stmt->fetchAll();

        } elseif ($id && $id !== 'children') {
            // GET /{collection}/:id — single record by numeric ID or pageslug
            $f = is_numeric($id) ? "id" : "pageslug";
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE $f = ? AND $pubClause");
            $stmt->execute([$id]);
            $rows = $stmt->fetchAll();

        } elseif ($typeFilter && $searchQuery) {
            // GET /{collection}?type=x&q=y — filter by type column AND search data
            $like = '%' . strtolower($searchQuery) . '%';
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE type = ? AND $pubClause AND LOWER(data) LIKE ?");
            $stmt->execute([$typeFilter, $like]);
            $rows = $stmt->fetchAll();

        } elseif ($typeFilter) {
            // GET /{collection}?type=x — filter by type column (category)
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE type = ? AND $pubClause");
            $stmt->execute([$typeFilter]);
            $rows = $stmt->fetchAll();

        } elseif ($searchQuery) {
            // GET /{collection}?q=x — search inside JSON data column
            $like = '%' . strtolower($searchQuery) . '%';
            $stmt = $pdo->prepare("SELECT * FROM $table WHERE $pubClause AND LOWER(data) LIKE ?");
            $stmt->execute([$like]);
            $rows = $stmt->fetchAll();

        } else {
            // GET /{collection} — full list
            $rows = $pdo->query("SELECT * FROM $table WHERE $pubClause")->fetchAll();
        }

        foreach ($rows as &$r) $r['data'] = json_decode($r['data']);
        api(($id && $id !== 'children' && count($rows) == 1) ? $rows[0] : $rows);
    }

    if ($method === 'POST') {
        // POST /{collection}
        // Body: { pageslug?, type?, belongsto?, data: { title, tags: [...], ... } }
        $slug      = (!empty($in['pageslug'])) ? createSlug($in['pageslug']) : createSlug($in['data']['title'] ?? 'untitled');
        $type      = $in['type']      ?? null;
        $belongsto = $in['belongsto'] ?? null;
        $pdo->prepare("INSERT INTO $table (user_id, pageslug, type, belongsto, data, is_published) VALUES (?, ?, ?, ?, ?, ?)")
            ->execute([$uID, $slug, $type, $belongsto, json_encode($in['data'] ?? []), ($role >= 2 ? 1 : 0)]);
        api(['id' => $pdo->lastInsertId(), 'slug' => $slug], 201);
    }

    if ($method === 'PATCH') {
        // PATCH /{collection}/:id
        // Merges incoming data{} fields into existing record. Does not wipe unlisted fields.
        // Also updates type, belongsto, and is_published if passed at top level.
        // Body: { data?: {...fields to merge}, type?, belongsto?, is_published?: 0|1 }
        if (!$id) api(['error' => 'ID or slug required for PATCH'], 400);
        $f = is_numeric($id) ? "id" : "pageslug";
        $existing = $pdo->prepare("SELECT * FROM $table WHERE $f = ?");
        $existing->execute([$id]);
        $record = $existing->fetch();
        if (!$record) api(['error' => 'Not found'], 404);
        $currentData  = json_decode($record['data'], true) ?? [];
        $newData      = array_merge($currentData, $in['data'] ?? []);
        $newPublished = isset($in['is_published']) ? (int)$in['is_published']  : $record['is_published'];
        $newType      = isset($in['type'])         ? $in['type']               : $record['type'];
        $newBelongsto = isset($in['belongsto'])     ? $in['belongsto']          : $record['belongsto'];
        $pdo->prepare("UPDATE $table SET data = ?, is_published = ?, type = ?, belongsto = ? WHERE $f = ?")
            ->execute([json_encode($newData), $newPublished, $newType, $newBelongsto, $id]);
        api(['status' => 'Updated', 'slug' => $record['pageslug']]);
    }

    if ($method === 'DELETE') {
        // DELETE /{collection}/:id
        if (!$id) api(['error' => 'ID required for DELETE'], 400);
        $pdo->prepare("DELETE FROM $table WHERE id = ?")->execute([$id]);
        api(['status' => 'Deleted']);
    }
}

switch ($res) {
    case 'stresstest':
    header('Content-Type: text/html');
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Phable Stress Test – Token Debug</title>
        <style>
            * { box-sizing: border-box; }
            body{font-family:sans-serif; max-width:1200px; margin:20px auto; background:#f0f2f5; color:#333; padding:20px;}
            .card{background:white; padding:20px; border-radius:10px; box-shadow:0 4px 6px rgba(0,0,0,0.05); margin-bottom:20px;}
            .flex{display:flex; gap:10px; align-items:center; flex-wrap:wrap;}
            table{width:100%; border-collapse:collapse; margin-top:10px;}
            th,td{border:1px solid #ddd; padding:8px; text-align:left;}
            th{background:#f8f9fa;}
            .status{font-weight:bold;}
            .green{color:green;}
            .red{color:red;}
            dialog{border:none; border-radius:10px; padding:30px; box-shadow:0 10px 30px rgba(0,0,0,0.2); max-width:600px; width:90%;}
            input,textarea,select{padding:8px; width:100%; margin-bottom:10px; border:1px solid #ddd; border-radius:5px; font-family:inherit;}
            button{background:#007bff; color:white; border:none; padding:8px 16px; border-radius:5px; cursor:pointer;}
            button.danger{background:#dc3545;}
            button.secondary{background:#6c757d;}
            .btn-group{display:flex; gap:5px; flex-wrap:wrap;}
            .endpoint-section{margin-bottom:30px;}
            .endpoint-title{font-size:1.2rem; font-weight:bold; margin-bottom:10px;}
            .add-btn{margin-bottom:10px;}
            .loading{opacity:0.5;}
            pre{background:#f4f4f4; padding:10px; border-radius:5px; overflow:auto;}
            .error-message{color:#dc3545; font-weight:bold; margin-top:10px;}
            .raw-response{background:#f8f9fa; padding:10px; border-radius:5px; font-family:monospace; white-space:pre-wrap; margin-top:10px; max-height:300px; overflow:auto;}
            .diagnostic{font-size:0.9em; color:#666; margin-top:5px;}
            .token-debug{border-left:4px solid #28a745; padding-left:15px; margin:20px 0;}
        </style>
    </head>
    <body>
        <h2>Phable Core v2.9.0 – Token Debug Stress Test</h2>
        <div class="card flex">
            <div id="auth-label">Mode: 👤 Guest</div>
            <button id="btn-log" onclick="document.getElementById('loginDialog').showModal()">Login</button>
            <button onclick="localStorage.removeItem('ph_token'); location.reload();">Logout</button>
        </div>
        <div class="card" id="role-info"></div>

        <!-- Token Debug Section -->
        <div class="card token-debug">
            <h3>🔍 Token Diagnostic</h3>
            <p>Your stored token (first 50 chars): <code id="tokenPreview">(none)</code></p>
            <p>Decoded role from token: <strong id="decodedRole">0</strong></p>
            <p><button onclick="testAuthHeader()">Test if server sees Authorization header</button></p>
            <div id="authTestResult" class="raw-response" style="display:none;"></div>
            <div class="diagnostic">
                <strong>If the server returns lvl:0 despite having a valid token,</strong> your PHP setup likely lacks <code>getallheaders()</code> (common on nginx).<br>
                You need to add a fallback in <code>index.php</code> – replace the line:<br>
                <code>$headers = getallheaders();</code><br>
                with:<br>
                <pre>
if (function_exists('getallheaders')) {
    $headers = getallheaders();
} else {
    $headers = [];
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) == 'HTTP_') {
            $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
        }
    }
}
                </pre>
            </div>
        </div>

        <!-- Manual HTTP Method Tester -->
        <div class="card">
            <h3>🛠 Manual HTTP Method Tester</h3>
            <p>Use this to test any endpoint with any method. The raw server response will be shown.</p>
            <div class="flex">
                <select id="testMethod">
                    <option>GET</option>
                    <option>POST</option>
                    <option>PATCH</option>
                    <option>DELETE</option>
                    <option>PUT</option>
                </select>
                <input type="text" id="testPath" placeholder="/phable" value="/phable" style="flex:2;">
            </div>
            <textarea id="testBody" rows="5" placeholder='{"title":"test"}' style="width:100%;">{"title":"test"}</textarea>
            <div class="btn-group">
                <button onclick="runManualTest()">Send Request</button>
                <button class="secondary" onclick="clearManualResult()">Clear</button>
            </div>
            <div id="manualResult" class="raw-response" style="display:none;"></div>
            <div id="manualError" class="error-message"></div>
        </div>

        <div id="endpoints-container"></div>

        <dialog id="loginDialog">
            <h3>Admin Login</h3>
            <input id="email" type="email" placeholder="Email" value="admin@local.test">
            <input id="password" type="password" placeholder="Password">
            <div class="btn-group">
                <button onclick="doLogin()">Authenticate</button>
                <button class="secondary" onclick="document.getElementById('loginDialog').close()">Cancel</button>
            </div>
        </dialog>

        <dialog id="formDialog"></dialog>

        <script>
            const API = window.location.href.split('stresstest')[0];
            let token = localStorage.getItem('ph_token');
            let currentRole = 0;

            async function req(method, path, body = null) {
                const headers = { 'Content-Type': 'application/json' };
                if (token) headers['Authorization'] = 'Bearer ' + token;
                const opts = { method, headers };
                if (body) opts.body = JSON.stringify(body);
                try {
                    const res = await fetch(API + path, opts);
                    const contentType = res.headers.get('content-type');
                    let data = null;
                    let text = null;
                    if (contentType && contentType.includes('application/json')) {
                        data = await res.json();
                    } else {
                        text = await res.text();
                    }
                    return { 
                        status: res.status, 
                        statusText: res.statusText,
                        headers: Object.fromEntries(res.headers.entries()),
                        data, 
                        text,
                        ok: res.ok,
                        url: res.url
                    };
                } catch (err) {
                    return { status: 0, error: err.message };
                }
            }

            function getRoleFromToken(t) {
                try {
                    const parts = t.split('.');
                    if (parts.length !== 3) return 0;
                    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
                    return payload.role || 0;
                } catch { return 0; }
            }

            if (token) {
                currentRole = getRoleFromToken(token);
                document.getElementById('auth-label').innerHTML = `Mode: 🔑 Authenticated (role ${currentRole})`;
                document.getElementById('tokenPreview').textContent = token.substring(0,50) + '...';
                document.getElementById('decodedRole').textContent = currentRole;
            }

            async function doLogin() {
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                const res = await req('POST', 'user/login', { email, password });
                if (res.data && res.data.token) {
                    localStorage.setItem('ph_token', res.data.token);
                    location.reload();
                } else {
                    alert('Login failed: ' + (res.data?.error || res.text || res.error || 'Unknown error'));
                }
            }

            async function testAuthHeader() {
                // We'll call a known endpoint that should echo the token if possible,
                // but since we can't modify the core, we'll just call /user and show the response.
                const res = await req('GET', 'user');
                const resultDiv = document.getElementById('authTestResult');
                resultDiv.style.display = 'block';
                resultDiv.innerHTML = `<strong>GET /user returned:</strong> HTTP ${res.status}<br>`;
                if (res.data) {
                    resultDiv.innerHTML += `<pre>${JSON.stringify(res.data, null, 2)}</pre>`;
                } else if (res.text) {
                    resultDiv.innerHTML += `<pre>${res.text}</pre>`;
                }
                if (res.data && res.data.lvl === 0) {
                    resultDiv.innerHTML += '<p class="red">⚠️ Server sees lvl:0 – token not recognized. This confirms the header is missing.</p>';
                }
            }

            async function fetchRoot() {
                return await req('GET', '');
            }

            async function render() {
                const root = await fetchRoot();
                const roleDiv = document.getElementById('role-info');
                roleDiv.innerHTML = `Server reports role (unauthenticated root call): <strong>${root.role}</strong> | Client decoded role: <strong>${currentRole}</strong>`;

                if (!root.endpoints) {
                    document.getElementById('endpoints-container').innerHTML = '<div class="card">No endpoint information available.</div>';
                    return;
                }

                const groups = {};
                for (const [base, endpoints] of Object.entries(root.endpoints)) {
                    groups[base] = endpoints;
                }

                const container = document.getElementById('endpoints-container');
                container.innerHTML = '';

                for (const [basePath, endpoints] of Object.entries(groups)) {
                    const section = document.createElement('div');
                    section.className = 'card endpoint-section';
                    section.dataset.path = basePath;

                    const title = document.createElement('div');
                    title.className = 'endpoint-title';
                    title.textContent = basePath;
                    section.appendChild(title);

                    const methodTable = document.createElement('table');
                    methodTable.innerHTML = `<thead><tr><th>Method</th><th>Path</th><th>Auth</th><th>Description</th></tr></thead>`;
                    const tbody = document.createElement('tbody');
                    endpoints.forEach(ep => {
                        const row = document.createElement('tr');
                        row.innerHTML = `<td>${ep.method}</td><td>${ep.path}</td><td>${ep.auth || '?'}</td><td>${ep.returns || ''}</td>`;
                        tbody.appendChild(row);
                    });
                    methodTable.appendChild(tbody);
                    section.appendChild(methodTable);

                    const collectionGet = endpoints.find(ep => ep.method === 'GET' && ep.path === basePath);
                    if (collectionGet) {
                        const dataDiv = document.createElement('div');
                        dataDiv.innerHTML = '<h4>Items</h4><div class="loading">Loading...</div>';
                        section.appendChild(dataDiv);

                        (async () => {
                            const res = await req('GET', basePath);
                            dataDiv.innerHTML = '';
                            if (res.status !== 200) {
                                dataDiv.innerHTML = `<span class="red">Error ${res.status}: ${res.data?.error || res.text || res.error || 'Unknown'}</span>`;
                                if (res.text) dataDiv.innerHTML += `<pre class="raw-response">${res.text}</pre>`;
                                return;
                            }
                            const items = res.data;
                            if (!Array.isArray(items)) {
                                dataDiv.innerHTML = '<p>Not a collection (single item response)</p>';
                                return;
                            }

                            const table = document.createElement('table');
                            table.innerHTML = '<thead><tr><th>ID</th><th>Slug</th><th>Type</th><th>Published</th><th>Actions</th></tr></thead>';
                            const tbody = document.createElement('tbody');
                            items.forEach(item => {
                                const row = document.createElement('tr');
                                row.innerHTML = `
                                    <td>${item.id}</td>
                                    <td>${item.pageslug || ''}</td>
                                    <td>${item.type || ''}</td>
                                    <td>${item.is_published ? '✅' : '❌'}</td>
                                    <td class="btn-group">
                                        <button onclick="viewItem('${basePath}', ${item.id})">View</button>
                                        ${currentRole >= 2 ? `<button onclick="editItem('${basePath}', ${item.id})">Edit</button>` : ''}
                                        ${currentRole >= 3 ? `<button class="danger" onclick="deleteItem('${basePath}', ${item.id})">Delete</button>` : ''}
                                    </td>
                                `;
                                tbody.appendChild(row);
                            });
                            table.appendChild(tbody);
                            dataDiv.appendChild(table);

                            if (currentRole >= 1 && endpoints.some(ep => ep.method === 'POST' && ep.path === basePath)) {
                                const addBtn = document.createElement('button');
                                addBtn.className = 'add-btn';
                                addBtn.textContent = '+ Add New';
                                addBtn.onclick = () => showAddForm(basePath);
                                dataDiv.prepend(addBtn);
                            }
                        })();
                    }

                    if (basePath === '/user' && currentRole >= 3) {
                        const userDiv = document.createElement('div');
                        userDiv.innerHTML = '<h4>Users</h4><div class="loading">Loading...</div>';
                        section.appendChild(userDiv);
                        (async () => {
                            const res = await req('GET', 'user');
                            userDiv.innerHTML = '';
                            if (res.status !== 200) {
                                userDiv.innerHTML = `<span class="red">Error ${res.status}</span>`;
                                if (res.text) userDiv.innerHTML += `<pre class="raw-response">${res.text}</pre>`;
                                return;
                            }
                            const users = res.data;
                            const table = document.createElement('table');
                            table.innerHTML = '<thead><tr><th>ID</th><th>Email</th><th>Role</th></tr></thead>';
                            const tbody = document.createElement('tbody');
                            users.forEach(u => {
                                const row = document.createElement('tr');
                                row.innerHTML = `<td>${u.id}</td><td>${u.email}</td><td>${u.role}</td>`;
                                tbody.appendChild(row);
                            });
                            table.appendChild(tbody);
                            userDiv.appendChild(table);
                        })();
                    }

                    container.appendChild(section);
                }

                const selfSection = document.createElement('div');
                selfSection.className = 'card';
                selfSection.innerHTML = '<div class="endpoint-title">/stresstest</div><p>This page. Use the manual tester to diagnose HTTP methods.</p>';
                container.appendChild(selfSection);
            }

            window.viewItem = async (basePath, id) => {
                const res = await req('GET', `${basePath}/${id}`);
                if (res.status !== 200) {
                    alert(`Error: ${res.data?.error || res.text || res.error || res.status}`);
                    return;
                }
                const dialog = document.getElementById('formDialog');
                dialog.innerHTML = `
                    <h3>Item #${id}</h3>
                    <pre>${JSON.stringify(res.data, null, 2)}</pre>
                    <button class="secondary" onclick="document.getElementById('formDialog').close()">Close</button>
                `;
                dialog.showModal();
            };

            window.editItem = async (basePath, id) => {
                const res = await req('GET', `${basePath}/${id}`);
                if (res.status !== 200) {
                    alert(`Cannot load item: ${res.data?.error || res.text || res.error}`);
                    return;
                }
                const item = res.data;
                const dialog = document.getElementById('formDialog');
                dialog.innerHTML = `
                    <h3>Edit Item #${id}</h3>
                    <form id="patchForm">
                        <label>Type</label>
                        <input name="type" value="${item.type || ''}" placeholder="type">
                        <label>Belongs To</label>
                        <input name="belongsto" value="${item.belongsto || ''}" placeholder="belongsto">
                        <label>Published</label>
                        <select name="is_published">
                            <option value="1" ${item.is_published ? 'selected' : ''}>Yes</option>
                            <option value="0" ${!item.is_published ? 'selected' : ''}>No</option>
                        </select>
                        <label>Data (JSON)</label>
                        <textarea name="data" rows="8" required>${JSON.stringify(item.data || {}, null, 2)}</textarea>
                        <div class="btn-group">
                            <button type="submit">Update (PATCH)</button>
                            <button type="button" class="secondary" onclick="document.getElementById('formDialog').close()">Cancel</button>
                        </div>
                    </form>
                    <div id="patch-error" class="error-message"></div>
                    <div id="patch-raw" class="raw-response"></div>
                `;
                dialog.showModal();

                document.getElementById('patchForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const form = e.target;
                    const body = {};
                    if (form.type.value) body.type = form.type.value;
                    if (form.belongsto.value) body.belongsto = form.belongsto.value;
                    body.is_published = parseInt(form.is_published.value);
                    try {
                        body.data = JSON.parse(form.data.value);
                    } catch (err) {
                        document.getElementById('patch-error').textContent = 'Invalid JSON in data field';
                        return;
                    }
                    const res = await req('PATCH', `${basePath}/${id}`, body);
                    if (res.status === 200) {
                        dialog.close();
                        location.reload();
                    } else {
                        let errorMsg = `Update failed: HTTP ${res.status}`;
                        if (res.data && res.data.error) errorMsg += ` - ${res.data.error}`;
                        else if (res.text) errorMsg += `\nRaw response: ${res.text}`;
                        else if (res.error) errorMsg += `\n${res.error}`;
                        document.getElementById('patch-error').textContent = errorMsg;
                        if (res.text) {
                            document.getElementById('patch-raw').textContent = res.text;
                        }
                    }
                });
            };

            window.deleteItem = async (basePath, id) => {
                if (!confirm('Delete this item?')) return;
                const res = await req('DELETE', `${basePath}/${id}`);
                if (res.status === 200) {
                    location.reload();
                } else {
                    let errorMsg = `Delete failed: HTTP ${res.status}`;
                    if (res.data && res.data.error) errorMsg += ` - ${res.data.error}`;
                    else if (res.text) errorMsg += `\nRaw response: ${res.text}`;
                    alert(errorMsg);
                }
            };

            function showAddForm(basePath) {
                const dialog = document.getElementById('formDialog');
                dialog.innerHTML = `
                    <h3>Add New Item to ${basePath}</h3>
                    <form id="addForm">
                        <label>Slug (optional)</label>
                        <input name="pageslug" placeholder="pageslug">
                        <label>Type</label>
                        <input name="type" placeholder="type">
                        <label>Belongs To</label>
                        <input name="belongsto" placeholder="belongsto">
                        <label>Data (JSON)</label>
                        <textarea name="data" rows="8" required>{"title":"New Item"}</textarea>
                        <div class="btn-group">
                            <button type="submit">Create (POST)</button>
                            <button type="button" class="secondary" onclick="document.getElementById('formDialog').close()">Cancel</button>
                        </div>
                    </form>
                    <div id="add-error" class="error-message"></div>
                    <div id="add-raw" class="raw-response"></div>
                `;
                dialog.showModal();

                document.getElementById('addForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const form = e.target;
                    const body = {};
                    if (form.pageslug.value) body.pageslug = form.pageslug.value;
                    if (form.type.value) body.type = form.type.value;
                    if (form.belongsto.value) body.belongsto = form.belongsto.value;
                    try {
                        body.data = JSON.parse(form.data.value);
                    } catch (err) {
                        document.getElementById('add-error').textContent = 'Invalid JSON in data field';
                        return;
                    }
                    const res = await req('POST', basePath, body);
                    if (res.status === 201) {
                        dialog.close();
                        location.reload();
                    } else {
                        let errorMsg = `Create failed: HTTP ${res.status}`;
                        if (res.data && res.data.error) errorMsg += ` - ${res.data.error}`;
                        else if (res.text) errorMsg += `\nRaw response: ${res.text}`;
                        else if (res.error) errorMsg += `\n${res.error}`;
                        document.getElementById('add-error').textContent = errorMsg;
                        if (res.text) {
                            document.getElementById('add-raw').textContent = res.text;
                        }
                    }
                });
            }

            window.runManualTest = async () => {
                const method = document.getElementById('testMethod').value;
                let path = document.getElementById('testPath').value;
                if (!path.startsWith('/')) path = '/' + path;
                const bodyText = document.getElementById('testBody').value;
                let body = null;
                if (bodyText.trim() && method !== 'GET' && method !== 'DELETE') {
                    try {
                        body = JSON.parse(bodyText);
                    } catch (e) {
                        document.getElementById('manualError').textContent = 'Invalid JSON in body';
                        return;
                    }
                }
                document.getElementById('manualError').textContent = '';
                const resultDiv = document.getElementById('manualResult');
                resultDiv.style.display = 'block';
                resultDiv.textContent = 'Sending...';
                const res = await req(method, path, body);
                let output = `HTTP ${res.status} ${res.statusText}\n\n`;
                if (res.headers) {
                    output += 'Headers:\n';
                    for (let [k, v] of Object.entries(res.headers)) {
                        output += `  ${k}: ${v}\n`;
                    }
                }
                output += '\n';
                if (res.data) {
                    output += 'JSON Response:\n' + JSON.stringify(res.data, null, 2);
                } else if (res.text) {
                    output += 'Raw Response:\n' + res.text;
                } else if (res.error) {
                    output += 'Error: ' + res.error;
                }
                resultDiv.textContent = output;
            };

            window.clearManualResult = () => {
                document.getElementById('manualResult').style.display = 'none';
                document.getElementById('manualError').textContent = '';
            };

            render();
        </script>
    </body>
    </html>
    <?php
    exit;

 case 'user':
    if ($id === 'login') {
        if(empty($in['email'])) api(['error'=>'No credentials'], 400);
        $u=$pdo->prepare("SELECT * FROM ph_users WHERE email=?"); 
        $u->execute([$in['email']]); 
        $user=$u->fetch();
        if ($user && password_verify($in['password'], $user['password'])) {
            $uRole = isset($user['role']) ? (int)$user['role'] : (($user['is_admin']??0) ? 3 : 1);
            $token = jwt_encode(['uid'=>$user['id'], 'role'=>$uRole, 'iat'=>time()], $secret);
            
            // DEBUG: Log successful login
            error_log("LOGIN SUCCESS: user_id={$user['id']}, role=$uRole, token generated");
            
            api(['status'=>'Success', 'token'=>$token, 'role'=>$uRole]);
        } 
        error_log("LOGIN FAILED: email={$in['email']}");
        api(['error'=>'Auth Failed'], 401);
    }
        check_rights([3,3,3,3]); 
        // Auto-migration: Check if 'role' exists, if not, create it
        try {
            api($pdo->query("SELECT id, email, role FROM ph_users")->fetchAll());
        } catch (Exception $e) {
            $pdo->exec("ALTER TABLE ph_users ADD COLUMN role TINYINT DEFAULT 1");
            $pdo->exec("UPDATE ph_users SET role = 3 WHERE is_admin = 1");
            api($pdo->query("SELECT id, email, role FROM ph_users")->fetchAll());
        }
        break;

    // -------------------------------------------------------------------------
    // COLLECTION HANDLER
    // -------------------------------------------------------------------------
    // A single function that provides full CRUD for any table that shares the
    // standard schema: id, user_id, pageslug, type, belongsto, is_published,
    // data (JSON), created_at.
    //
    // Usage from a switch case:
    //   collection_handler('ph_mytable', [0, 1, 2, 3], $pdo, $id, $subId, $in, $uID, $role);
    //
    // Usage from plugins.php:
    //   function handle_plugins($res, $id, $subId, $in, $pdo, $uID, $role) {
    //       if ($res === 'presentations') {
    //           collection_handler('ph_presentations', [0, 1, 2, 3], $pdo, $id, $subId, $in, $uID, $role);
    //       }
    //   }
    //   Note: handle_plugins is only called for Admin users (role 3).
    //   Plugin routes are not accessible to Visitors, Users, or Editors.
    //
    // Rights matrix: [GET, POST, PATCH, DELETE] — minimum role required per method.
    //   0 = Visitor (public), 1 = User, 2 = Editor, 3 = Admin
    //
    // The table must exist. Use the installer or run the CREATE TABLE manually.
    // Standard CREATE: id INT AI PK, user_id INT, pageslug VARCHAR(255) UNIQUE,
    //   type VARCHAR(50), belongsto VARCHAR(50), is_published TINYINT(1) DEFAULT 0,
    //   data JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    // -------------------------------------------------------------------------

    case 'phable':
        // phable is the first built-in collection — registered directly in the switch.
        // This proves the collection_handler pattern works without a plugin file.
        collection_handler('ph_phables', [0, 1, 2, 3], $pdo, $id, $subId, $in, $uID, $role);
        break;

    case 'blocks':
        collection_handler('ph_blocks', [0, 1, 2, 3], $pdo, $id, $subId, $in, $uID, $role);
        break;

    default:
        // PLUGIN BRIDGE
        // Requires a logged-in user (role 1+) to reach any plugin endpoint.
        // Unauthenticated visitors hitting unknown routes get the info response below.
        // Access control per plugin is handled inside handle_plugins() via check_rights().
        // Who can REGISTER plugins is controlled by server file access to plugins.php — 
        // that is the admin boundary, not this gate.
        if (file_exists($pluginFile) && $role >= 1) { 
            include_once $pluginFile; 
            if (function_exists('handle_plugins')) handle_plugins($res, $id, $subId, $in, $pdo, $uID, $role); 
        }

        // Root API response: version, current auth role, and full endpoint reference.
        // Not for production — remove or gate behind $isAdmin when going live.
        api([
            'status'  => 'online',
            'v'       => '2.9.0',
            'role'    => $role,
            'endpoints' => [

                '/user' => [
                    ['method'=>'POST', 'path'=>'/user/login', 'auth'=>'none',       'body'=>['email','password'],  'returns'=>'JWT token + role'],
                    ['method'=>'GET',  'path'=>'/user',       'auth'=>'Admin (3)',  'body'=>null,                  'returns'=>'All users (id, email, role)'],
                ],

                '/phable' => [
                    ['method'=>'GET',    'path'=>'/phable',     'auth'=>'Public',    'body'=>null,                                          'returns'=>'Published docs. Editor+ sees all.'],
                    ['method'=>'GET',    'path'=>'/phable/:id', 'auth'=>'Public',    'body'=>null,                                          'returns'=>'Single doc by ID or slug'],
                    ['method'=>'POST',   'path'=>'/phable',     'auth'=>'User (1)',  'body'=>['pageslug?','type?','data{title,...}'],        'returns'=>'Created id + slug'],
                    ['method'=>'PATCH',  'path'=>'/phable/:id', 'auth'=>'Editor (2)','body'=>['data{...fields to merge}','type?','belongsto?','is_published?'],  'returns'=>'Updated slug'],
                    ['method'=>'DELETE', 'path'=>'/phable/:id', 'auth'=>'Admin (3)', 'body'=>null,                                          'returns'=>'Deleted status'],
                ],

                '/blocks' => [
                    ['method'=>'GET',    'path'=>'/blocks',              'auth'=>'Public',    'params'=>['type'=>'filter by category','q'=>'search inside data'], 'returns'=>'Blocks. Filterable by ?type= and ?q='],
                    ['method'=>'GET',    'path'=>'/blocks/:id',          'auth'=>'Public',    'body'=>null,                                                       'returns'=>'Single block by ID or slug'],
                    ['method'=>'GET',    'path'=>'/blocks/children/:id', 'auth'=>'Public',    'body'=>null,                                                       'returns'=>'Child blocks by parent ID or slug'],
                    ['method'=>'POST',   'path'=>'/blocks',              'auth'=>'User (1)',  'body'=>['pageslug?','type?','belongsto?','data{title,tags,...}'],   'returns'=>'Created id + slug'],
                    ['method'=>'PATCH',  'path'=>'/blocks/:id',          'auth'=>'Editor (2)','body'=>['data{...fields to merge}','type?','belongsto?','is_published?'],  'returns'=>'Updated slug'],
                    ['method'=>'DELETE', 'path'=>'/blocks/:id',          'auth'=>'Admin (3)', 'body'=>null,                                                       'returns'=>'Deleted status'],
                ],

                // Any collection registered via collection_handler() gets the same endpoints.
                // To add one from plugins.php:
                //   if ($res === 'presentations') collection_handler('ph_presentations', [0,1,2,3], $pdo, $id, $subId, $in, $uID, $role);

                '/stresstest' => [
                    ['method'=>'GET', 'path'=>'/stresstest', 'auth'=>'none', 'body'=>null, 'returns'=>'Built-in UI test page (HTML)'],
                ],

            ],
        ]);
}
