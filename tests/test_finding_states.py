import os
import asyncio
from app import db


def test_compute_state_transitions(tmp_path):
    db_file = os.path.join(os.path.dirname(__file__), '..', 'data.db')
    if os.path.exists(db_file):
        os.remove(db_file)

    async def run():
        await db.init_db()
        s1 = await db.create_scan('example.com')
        await db.add_finding(s1,'h','1.1.1.1',80,'tcp','low','A','',{})
        await db.add_finding(s1,'h','1.1.1.1',443,'tcp','low','B','',{})
        t1 = await db.compute_state_transitions(s1)
        assert t1['new'] == {'h|1.1.1.1|80|tcp|A','h|1.1.1.1|443|tcp|B'}
        assert t1['resolved'] == set()
        assert t1['regressed'] == set()
        s2 = await db.create_scan('example.com')
        await db.add_finding(s2,'h','1.1.1.1',443,'tcp','low','B','',{})
        await db.add_finding(s2,'h','1.1.1.1',8080,'tcp','low','C','',{})
        t2 = await db.compute_state_transitions(s2)
        assert t2['new'] == {'h|1.1.1.1|8080|tcp|C'}
        assert t2['resolved'] == {'h|1.1.1.1|80|tcp|A'}
        assert t2['regressed'] == set()
        s3 = await db.create_scan('example.com')
        await db.add_finding(s3,'h','1.1.1.1',80,'tcp','low','A','',{})
        await db.add_finding(s3,'h','1.1.1.1',8080,'tcp','low','C','',{})
        t3 = await db.compute_state_transitions(s3)
        assert t3['new'] == set()
        assert t3['resolved'] == {'h|1.1.1.1|443|tcp|B'}
        assert t3['regressed'] == {'h|1.1.1.1|80|tcp|A'}

    asyncio.run(run())
