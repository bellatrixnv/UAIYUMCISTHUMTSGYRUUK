import aiosqlite, asyncio, json, os, time
from .state_transition import state_transition as _state_transition
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
CREATE TABLE IF NOT EXISTS finding_states(
  scan_id INTEGER NOT NULL,
  dedupe_key TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('open','resolved')),
  PRIMARY KEY (scan_id, dedupe_key)

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


async def _list_dedupe_keys(scan_id:int)->set[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT host, ip, port, proto, title FROM findings WHERE scan_id=?",
            (scan_id,),
        )
        rows = await cur.fetchall()
    return {
        f"{r['host']}|{r['ip'] or ''}|{r['port'] or ''}|{r['proto'] or ''}|{r['title']}"
        for r in rows
    }


async def _prev_open_keys(scan_id:int)->set[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT domain FROM scans WHERE id=?", (scan_id,))
        row = await cur.fetchone()
        if not row:
            return set()
        domain = row["domain"]
        cur = await db.execute(
            "SELECT id FROM scans WHERE domain=? AND id<? ORDER BY id DESC LIMIT 1",
            (domain, scan_id),
        )
        prev = await cur.fetchone()
        if not prev:
            return set()
        prev_id = prev["id"]
        cur = await db.execute(
            "SELECT dedupe_key FROM finding_states WHERE scan_id=? AND state='open'",
            (prev_id,),
        )
        return {r["dedupe_key"] for r in await cur.fetchall()}


async def _last_states(scan_id:int)->dict[str,str]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT dedupe_key, state FROM finding_states WHERE scan_id < ? ORDER BY scan_id DESC",
            (scan_id,),
        )
        rows = await cur.fetchall()
    last:dict[str,str] = {}
    for r in rows:
        key = r["dedupe_key"]
        if key not in last:
            last[key] = r["state"]
    return last


async def _record_states(scan_id:int, open_keys:set[str], resolved_keys:set[str]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executemany(
            "INSERT INTO finding_states(scan_id,dedupe_key,state) VALUES(?,?,?)",
            [(scan_id, k, 'open') for k in open_keys]
            + [(scan_id, k, 'resolved') for k in resolved_keys],
        )
        await db.commit()


async def compute_state_transitions(scan_id:int)->dict[str,set[str]]:
    curr = await _list_dedupe_keys(scan_id)
    prev = await _prev_open_keys(scan_id)
    diff = _state_transition(prev, curr)
    last = await _last_states(scan_id)
    regressed = {k for k in diff['new'] if last.get(k) == 'resolved'}
    new = diff['new'] - regressed
    await _record_states(scan_id, curr, diff['resolved'])
    return {'new': new, 'resolved': diff['resolved'], 'regressed': regressed}
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
