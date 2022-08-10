from logging import exception
from random import randint
import sqlite3
import string

from flask import session


class Encrypt:

    def encryption(password, key):
        encrypted = []
        for c in password:
            new = ord(c) + key
            if new > 126:
                new = new - 126 + 33
            encrypted.append(chr(new))

        return ''.join(encrypted)

    def decryption(password, key):
        '''if password is not int:
            raise ValueError("int")
        if password is not str:
            raise ValueError("str")'''
        decrypted = []
        for c in password:
            original = ord(c) - key
            if original < 33:
                original = original + 126 - 33
            decrypted.append(chr(original))
            
        return ''.join(decrypted)

def create(n):
    chars = string.ascii_letters
    nums = string.digits
    specials = string.punctuation
    all_chars = chars + nums + specials
    password = chars[randint(0, (len(chars) - 1))]
    while n > 1:
        password = password + all_chars[randint(0, (len(all_chars) - 1))]
        n = n - 1
    return password

'''db = sqlite3.connect("project.db", check_same_thread=False)
cursor = db.cursor()

#create a table for users
cursor.execute("CREATE TABLE IF NOT EXISTS users(id integer PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL)")
db.commit()

 #Create a table for keep track of storing passwords
cursor.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER, cipher TEXT NOT NULL, key INTEGER, name TEXT, description TEXT, time TEXT NOT NULL)")
db.commit()

cursor.execute("SELECT * FROM passwords")
rows = cursor.fetchall()
db.commit()

print(rows)'''