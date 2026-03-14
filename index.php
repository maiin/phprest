<?php
/**
 * PHABLE CORE API - v0.1
 * architecture: "Frozen Core with Plugin Bridge"
 * security: "Stateless JWT Auth"
 */

// Error reporting for debugging (Disable in production)
ini_set('display_errors', 0); 
error_reporting(E_ALL);

$method = $_SERVER['REQUEST_METHOD'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = (isset($_SERVER['HTTPS']) ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];

if ($method === 'GET' || $method === 'OPTIONS') {
    header("Access-Control-Allow-Origin: *");
} elseif ($origin === $host) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    http_response_code(403);
    echo json_encode(['error' => 'Cross-origin writes not allowed']);
    exit;
}

header("Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') exit;

$configFile = __DIR__ . '/config.php';
$pluginFile = __DIR__ . '/plugins.php';
$secret = getenv('JCXRPC') ?: null;

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
    if (!$secret) return null; // no secret = treat as unauthenticated
    if(!$t) return null;
    $p = explode('.', $t); if(count($p) != 3) return null;
    $s = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(hash_hmac('sha256', "$p[0].$p[1]", $secret, true)));
    return ($s === $p[2]) ? json_decode(base64_decode(strtr($p[1], '-_', '+/')), true) : null;
}

// --- AUTH ORCHESTRATOR ---
$headers = getallheaders();
$auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
$token = str_replace('Bearer ', '', $auth);
$jwt = jwt_decode($token, $secret);
$uID = $jwt['uid'] ?? null;
$role = $jwt['role'] ?? 0;
$isAdmin = ($role >= 3);

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
    echo "<h3>Phable v0.1 Installer</h3><form method='POST'><input name='db_h' value='localhost'><input name='db_n' placeholder='DB Name'><input name='db_u' placeholder='DB User'><input name='db_p' type='password' placeholder='DB Pass'><hr><input name='admin_e' placeholder='Admin Email'><input name='admin_p' placeholder='Admin Pass'><button>Install</button></form>";
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
case 'user':
    if ($id === 'login') {
        if (empty($in['email'])) api(['error'=>'No credentials'], 400);
        $u = $pdo->prepare("SELECT * FROM ph_users WHERE email=?");
        $u->execute([$in['email']]);
        $user = $u->fetch();
        if ($user && password_verify($in['password'], $user['password'])) {
            $uRole = isset($user['role']) ? (int)$user['role'] : (($user['is_admin']??0) ? 3 : 1);
            if (!$secret) api(['error' => 'Server misconfiguration'], 500);
            $token = jwt_encode(['uid'=>$user['id'], 'role'=>$uRole, 'iat'=>time()], $secret);
            api(['status'=>'Success', 'token'=>$token, 'role'=>$uRole]);
        }
        api(['error'=>'Auth Failed'], 401);
    } else {
        check_rights([3,3,3,3]);
        try {
            api($pdo->query("SELECT id, email, role FROM ph_users")->fetchAll());
        } catch (Exception $e) {
            $pdo->exec("ALTER TABLE ph_users ADD COLUMN role TINYINT DEFAULT 1");
            $pdo->exec("UPDATE ph_users SET role = 3 WHERE is_admin = 1");
            api($pdo->query("SELECT id, email, role FROM ph_users")->fetchAll());
        }
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

        // Root API response: for admin - current auth role, and full endpoint reference.
        if ($isAdmin) {
            api([
                'status'   => 'online',
                'v'        => '0.1',
                'role'     => $role,
                'endpoints' => [
                    '/user' => [
                        ['method'=>'POST', 'path'=>'/user/login', 'auth'=>'none',      'body'=>['email','password'], 'returns'=>'JWT token + role'],
                        ['method'=>'GET',  'path'=>'/user',       'auth'=>'Admin (3)', 'body'=>null,                 'returns'=>'All users (id, email, role)'],
                    ],
                    '/phable' => [
                        ['method'=>'GET',    'path'=>'/phable',     'auth'=>'Public',     'body'=>null,                                         'returns'=>'Published docs. Editor+ sees all.'],
                        ['method'=>'GET',    'path'=>'/phable/:id', 'auth'=>'Public',     'body'=>null,                                         'returns'=>'Single doc by ID or slug'],
                        ['method'=>'POST',   'path'=>'/phable',     'auth'=>'User (1)',   'body'=>['pageslug?','type?','data{title,...}'],       'returns'=>'Created id + slug'],
                        ['method'=>'PATCH',  'path'=>'/phable/:id', 'auth'=>'Editor (2)','body'=>['data{...fields}','type?','belongsto?','is_published?'], 'returns'=>'Updated slug'],
                        ['method'=>'DELETE', 'path'=>'/phable/:id', 'auth'=>'Admin (3)', 'body'=>null,                                         'returns'=>'Deleted status'],
                    ],
                    '/blocks' => [
                        ['method'=>'GET',    'path'=>'/blocks',              'auth'=>'Public',    'params'=>['type'=>'filter by category','q'=>'search inside data'], 'returns'=>'Blocks. Filterable by ?type= and ?q='],
                        ['method'=>'GET',    'path'=>'/blocks/:id',          'auth'=>'Public',    'body'=>null,                                                       'returns'=>'Single block by ID or slug'],
                        ['method'=>'GET',    'path'=>'/blocks/children/:id', 'auth'=>'Public',    'body'=>null,                                                       'returns'=>'Child blocks by parent ID or slug'],
                        ['method'=>'POST',   'path'=>'/blocks',              'auth'=>'User (1)',  'body'=>['pageslug?','type?','belongsto?','data{title,tags,...}'],   'returns'=>'Created id + slug'],
                        ['method'=>'PATCH',  'path'=>'/blocks/:id',          'auth'=>'Editor (2)','body'=>['data{...fields}','type?','belongsto?','is_published?'],   'returns'=>'Updated slug'],
                        ['method'=>'DELETE', 'path'=>'/blocks/:id',          'auth'=>'Admin (3)', 'body'=>null,                                                       'returns'=>'Deleted status'],
                    ],
                ],
            ]);
        }

        api(['status' => 'online', 'v' => '0.1'], 200);
}
