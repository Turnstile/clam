import sqlite3

conn = sqlite3.connect('./local_db.sqlite3')
c = conn.cursor()
c.execute("select * from quarantine")
result = c.fetchall()
print(result)
c.execute("select * from approved")
result = c.fetchall()
print(result)
c.close()
conn.close()
