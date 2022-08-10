import sqlite3
db = sqlite3.connect("students.db", check_same_thread=False)
cursor = db.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS studes(id INTEGER PRIMARY KEY, roll_no INTEGER, name TEXT)")
'''cursor.execute("INSERT INTO studs (roll_no, name) VALUES (?, ?)", ("4", "dfffds"))
db.commit()

cursor.execute("CREATE INDEX IF NOT EXISTS inde ON studs (roll_no, name)")
db.commit()'''

#PRAGMA index_list("studs");

cursor.execute("CREATE SEQUENCE students.seq START WITH 1 INCREMENT BY 1 MINVALUE 1 MAXVALUE 3 NOCYCLE")
db.commit()

cursor.execute("INSERT INTO studes (roll_no) VALUES (seq.nextval, ?", ("4"))
db.commit()