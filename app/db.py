import aiosqlite, asyncio, json, os, time
from . import fix_queue

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
  owner_email TEXT,
  criticality INTEGER,
  data_class TEXT,
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

async def upsert_asset(scan_id:int, host:str, ip:str|None, *, owner_email:str|None=None,
                       criticality:int|None=None, data_class:str|None=None):
    now = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO assets(scan_id,host,ip,owner_email,criticality,data_class,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?)",
            (scan_id, host, ip, owner_email, criticality, data_class, now, now))
        await db.execute(
            """
            UPDATE assets SET last_seen=?,
                owner_email=COALESCE(?,owner_email),
                criticality=COALESCE(?,criticality),
                data_class=COALESCE(?,data_class)
            WHERE scan_id=? AND host=? AND ifnull(ip,'')=ifnull(?, '')
            """,
            (now, owner_email, criticality, data_class, scan_id, host, ip))
        await db.commit()

async def add_finding(scan_id:int, host:str, ip:str|None, port:int|None, proto:str|None,
                      severity:str, title:str, description:str, evidence:dict):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("""INSERT INTO findings
            (scan_id,host,ip,port,proto,severity,title,description,evidence_json,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (scan_id,host,ip,port,proto,severity,title,description,json.dumps(evidence),int(time.time())))
        finding_id = cur.lastrowid
        owner_email = None
        cur = await db.execute(
            "SELECT owner_email FROM assets WHERE scan_id=? AND host=? AND ifnull(ip,'')=ifnull(?, '')",
            (scan_id, host, ip))
        row = await cur.fetchone()
        if row:
            owner_email = row[0]
        await db.commit()
    if severity in ("high", "critical"):
        fix_queue.add(finding_id, owner_email, severity, title, description)
        fix_queue.open_jira_ticket(finding_id, title, description, owner_email)

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
