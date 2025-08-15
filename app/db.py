import aiosqlite, asyncio, json, os, time
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data.db")

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT NOT NULL CHECK(status IN ('queued','running','done','error')) DEFAULT 'queued',
  stats_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  ip TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  UNIQUE(scan_id, host, ip)
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  ip TEXT,
  port INTEGER,
  proto TEXT,
  severity TEXT NOT NULL CHECK(severity IN ('info','low','medium','high','critical')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connectors(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org TEXT NOT NULL DEFAULT 'default',
  kind TEXT NOT NULL CHECK(kind IN ('aws')),
  role_arn TEXT NOT NULL,
  external_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scope(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org TEXT NOT NULL DEFAULT 'default',
  kind TEXT NOT NULL CHECK(kind IN ('domain','cidr')),
  value TEXT NOT NULL
);
"""

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()

async def create_scan(domain:str)->int:
    now = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("INSERT INTO scans(domain,started_at,status) VALUES(?,?,?)",
                               (domain, now, 'running'))
        await db.commit()
        return cur.lastrowid

async def finish_scan(scan_id:int, status:str, stats:dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE scans SET finished_at=?, status=?, stats_json=? WHERE id=?",
                         (int(time.time()), status, json.dumps(stats), scan_id))
        await db.commit()

async def upsert_asset(scan_id:int, host:str, ip:str|None):
    now = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO assets(scan_id,host,ip,first_seen,last_seen) VALUES(?,?,?,?,?)",
            (scan_id, host, ip, now, now))
        await db.execute(
            "UPDATE assets SET last_seen=? WHERE scan_id=? AND host=? AND ifnull(ip,'')=ifnull(?, '')",
            (now, scan_id, host, ip))
        await db.commit()

async def add_finding(scan_id:int, host:str, ip:str|None, port:int|None, proto:str|None,
                      severity:str, title:str, description:str, evidence:dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""INSERT INTO findings
            (scan_id,host,ip,port,proto,severity,title,description,evidence_json,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (scan_id,host,ip,port,proto,severity,title,description,json.dumps(evidence),int(time.time())))
        await db.commit()

async def get_scan(scan_id:int)->dict|None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        row = await cur.fetchone()
        return dict(row) if row else None

async def list_scans()->list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scans ORDER BY id DESC")
        return [dict(r) for r in await cur.fetchall()]

async def list_findings(scan_id:int)->list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))
        return [dict(r) for r in await cur.fetchall()]

async def add_connector_aws(role_arn:str, external_id:str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO connectors(org,kind,role_arn,external_id,created_at) VALUES(?,?,?,?,?)",
                         ('default','aws',role_arn,external_id,int(time.time())))
        await db.commit()

async def get_connectors(kind:str='aws')->list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM connectors WHERE kind=?", (kind,))
        return [dict(r) for r in await cur.fetchall()]

async def add_scope(org:str, kind:str, value:str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO scope(org,kind,value) VALUES(?,?,?)",
                         (org, kind, value))
        await db.commit()

async def list_scope(org:str='default')->list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM scope WHERE org=?", (org,))
        return [dict(r) for r in await cur.fetchall()]

async def domain_in_scope(domain:str, org:str='default')->bool:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT kind,value FROM scope WHERE org=?", (org,))
        rows = await cur.fetchall()
        domain = domain.lower()
        for r in rows:
            if r["kind"] == "domain":
                val = r["value"].lower()
                if domain == val or domain.endswith("." + val):
                    return True
        return False
