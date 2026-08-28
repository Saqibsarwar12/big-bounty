// Real wordlists — curated subsets of SecLists (github.com/danielmiessler/SecLists)
// and common bug-bounty dictionaries. Embedded for zero-latency serverless use.

// Sensitive/exposed paths — dirb-style brute force targets
const PATHS = [
  '/.env', '/.git/HEAD', '/.git/config', '/.gitignore', '/.htaccess', '/.htpasswd',
  '/.DS_Store', '/.svn/entries', '/.well-known/security.txt', '/.bak', '/backup.sql',
  '/.aws/credentials', '/.ssh/id_rsa', '/server-status', '/server-info',
  '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
  '/admin', '/admin/', '/admin/login', '/adminer.php', '/admin.php', '/administrator/',
  '/api', '/api/', '/api/v1', '/api/v2', '/api/docs', '/api/swagger', '/swagger',
  '/swagger.json', '/swagger/ui', '/openapi.json', '/api-docs', '/docs', '/documentation',
  '/graphql', '/graphiql', '/api/graphql', '/playground', '/console',
  '/actuator', '/actuator/health', '/actuator/env', '/actuator/heapdump',
  '/phpinfo.php', '/info.php', '/test.php', '/debug', '/debug/vars', '/_debug',
  '/wp-admin/', '/wp-login.php', '/wp-json/', '/wp-config.php', '/wp-content/debug.log',
  '/xmlrpc.php', '/readme.html', '/wp-content/uploads/',
  '/config.php', '/config.json', '/config.yml', '/configuration.php', '/settings.php',
  '/local.xml', '/database.yml', '/db.sqlite', '/database.sql', '/dump.sql',
  '/composer.json', '/composer.lock', '/package.json', '/yarn.lock', '/web.config',
  '/backup', '/backup.zip', '/backup.tar.gz', '/backup.old', '/backups/', '/site-backup.zip',
  '/db.sql', '/database.sql', '/data.sql', '/dump.sql.gz',
  '/.env.local', '/.env.production', '/.env.backup', '/env.example', '/.env.example',
  '/.npmrc', '/.dockerenv', '/Dockerfile', '/docker-compose.yml',
  '/.aws/credentials', '/credentials', '/credentials.txt', '/secret.txt', '/secrets.json',
  '/id_rsa', '/id_rsa.pub', '/private.key', '/server.key', '/keystore.jks',
  '/error.log', '/access.log', '/debug.log', '/app.log', '/logs/', '/log/',
  '/phpmyadmin/', '/pma/', '/mysql/', '/sql/', '/setup/', '/install/', '/install.php',
  '/cgi-bin/', '/cgi-bin/test.cgi', '/shell', '/cmd', '/terminal',
  '/jenkins/', '/jira/', '/confluence/', '/gitlab/', '/kibana/', '/grafana/',
  '/solr/', '/elasticsearch/', '/_cat/indices', '/.kibana',
  '/tomcat-docs/', '/manager/html', '/host-manager/', '/examples/jsp/',
  '/webapps/', '/web-inf/web.xml', '/WEB-INF/web.xml', '/META-INF/MANIFEST.MF',
  '/springboot', '/trace', '/env', '/health', '/metrics', '/status',
  '/.travis.yml', '/.circleci/config.yml', '/Jenkinsfile', '/.github/workflows',
  '/temp/', '/tmp/', '/test/', '/tests/', '/dev/', '/old/', '/new/', '/beta/',
  '/phpunit.xml', '/phpunit.xml.dist', '/coverage/', '/report/',
  '/register', '/signup', '/user/register', '/users', '/user', '/members',
  '/changelog.txt', '/CHANGELOG.md', '/readme.md', '/README.md', '/TODO.txt', '/todo.txt',
  '/.well-known/host-meta', '/favicon.ico', '/apple-touch-icon.png',
  '/owa/', '/ews/', '/autodiscover/', '/.well-known/openid-configuration',
  '/rest', '/rest/v1/', '/v1', '/v2', '/v3', '/api/rest', '/service', '/wsdl',
];

// Parameter names to fuzz (params commonly found in real apps)
const PARAMS = [
  'q', 'query', 'search', 's', 'keyword', 'id', 'user', 'username', 'email',
  'page', 'p', 'sort', 'order', 'filter', 'name', 'cat', 'category', 'type',
  'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return', 'returnUrl',
  'lang', 'locale', 'debug', 'test', 'admin', 'file', 'path', 'dir', 'template',
  'include', 'view', 'action', 'cmd', 'exec', 'callback', 'jsonp',
];

// Subdomain candidates (top common — resolved via real DNS)
const SUBDOMAINS = [
  'www2', 'mail', 'email', 'webmail', 'smtp', 'ftp', 'cpanel', 'whm', 'webdisk',
  'api', 'dev', 'staging', 'stage', 'test', 'testing', 'qa', 'uat', 'demo', 'beta',
  'admin', 'portal', 'intranet', 'internal', 'vpn', 'remote', 'cdn', 'static',
  'assets', 'img', 'images', 'media', 'files', 'download', 'docs', 'documentation',
  'wiki', 'blog', 'shop', 'store', 'app', 'mobile', 'm', 'wap', 'oauth', 'auth',
  'sso', 'login', 'account', 'id', 'git', 'gitlab', 'jenkins', 'ci', 'jira',
  'confluence', 'kibana', 'grafana', 'monitor', 'status', 'db', 'database', 'mysql',
  'sql', 'postgres', 'redis', 'elastic', 'es', 'search', 'solr', 'kafka',
  'rabbitmq', 'queue', 'ns1', 'ns2', 'dns', 'mx', 'gateway', 'proxy', 'lb',
  'backup', 'old', 'legacy', 'archive', 'sandbox', 'support', 'help', 'crm',
  'erp', 'hr', 'intranet2', 'internal', 'secret', 'private', 'secure', 'ssl',
];

// XSS payloads — canary + probe (must be safely testable via GET)
const XSS_CANARY = 'bbcantry7x4k';
const XSS_PAYLOADS = [
  '"><svg/onload=bbcantry()>',
  `'><img src=x onerror=alert("${XSS_CANARY}")>`,
  '<svg onload=alert(1)>',
  'javascript:alert(1)',
];

// SQLi probes — error-based signatures (safe: read-only payloads)
const SQLI_PAYLOADS = [
  { p: "'", d: 'quote error' },
  { p: "1'", d: 'quote error' },
  { p: '1 OR 1=1', d: 'tautology' },
  { p: "1' OR '1'='1", d: 'string tautology' },
  { p: '1 UNION SELECT NULL', d: 'union probe' },
  { p: "1 AND SLEEP(0)", d: 'time probe' },
  { p: '1 WAITFOR DELAY', d: 'time probe mssql' },
  { p: "1; SELECT 1", d: 'stacked query' },
];
const SQL_ERROR_SIGNATURES = [
  'you have an error in your sql syntax', 'warning: mysql', 'unclosed quotation mark',
  'quoted string not properly terminated', 'mysql_fetch', 'mysqli_', 'pg_query',
  'postgresql', 'sqlite_master', 'sqlite3.', 'sqlstate', 'odbc', 'oracle error',
  'ora-00933', 'ora-01756', 'microsoft ole db provider', 'sqlserver jdbc',
  'syntax error at or near', 'fatal: password authentication', 'sqlite.OperationalError',
  'psql: fatal', 'psycopg2', 'unexpected end of sql statement', 'exception: sql',
];

// Open redirect probes
const REDIRECT_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'url', 'next', 'return',
  'returnUrl', 'returnTo', 'goto', 'target', 'dest', 'destination', 'r',
  'continue', 'link', 'u', 'forward', 'out', 'view',
];
const REDIRECT_PAYLOADS = [
  'https://bbcantry.example.com',
  '//bbcantry.example.com',
];

// Common HTTP ports (only checked over HTTP(S) — no raw sockets in serverless)
const COMMON_PORTS_HTTP = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 1337, 4443, 8443];

module.exports = {
  PATHS, PARAMS, SUBDOMAINS, XSS_CANARY, XSS_PAYLOADS,
  SQLI_PAYLOADS, SQL_ERROR_SIGNATURES, REDIRECT_PARAMS, REDIRECT_PAYLOADS,
  COMMON_PORTS_HTTP,
};