import getpass
import colorama
from colorama import Fore, Back, Style

import sqlite3
import base64

import time
import string
import random

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

NORMAL =   Style.NORMAL + Back.BLACK + Fore.WHITE
NORMAL =   Style.NORMAL + Back.BLACK + Fore.WHITE
SUCCESS =  Style.NORMAL + Back.BLACK + Fore.GREEN
ERROR =    Style.NORMAL + Back.BLACK + Fore.RED
WARN =     Style.NORMAL + Back.BLACK + Fore.YELLOW
INFO =     Style.NORMAL + Back.BLACK + Fore.CYAN

PASSWORD = Style.NORMAL + Back.BLUE + Fore.BLUE


colorama.init()

def iinput(txt):
    print(txt, end="")
    return input()

def iigetpass(txt):
    print(txt, end="")
    return getpass.getpass()


class Input():
    def __init__(self, txt):
        self.raw = iinput(txt)
        self.i = [x.strip() for x in self.raw.strip().split()]

    def iscmd(self, txt, n=0):
        try:
            return txt.strip() == self.i[n]
        except IndexError:
            return False

    def get(self, n=0):
        try:
            return self.i[n]
        except IndexError:
            return None



class key:
    def __init__(self, user, password):
        password = password.encode()
        user = user.encode() #os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=user,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

        self.key = key.decode()

    def encrypt(self, data):
        return Fernet(self.key).encrypt(data.encode()).decode()

    def decrypt(self, data):
        return Fernet(self.key).decrypt(data.encode()).decode()



class main():
    def __init__(self, *args, **kwords):
        super().__init__(*args, **kwords)

        self.comnection = sqlite3.connect('data.db')
        self.cursor = self.comnection.cursor()

        print(SUCCESS + "Connected.")

        sql_command = """
        CREATE TABLE IF NOT EXISTS services  (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT,
        email Text,
        username Text,
        pass Text,
        notes Text
        )"""
        self.cursor.execute(sql_command)

        print(INFO + "Table check")

    def finds(self, term):
        sql_command = "SELECT * FROM services WHERE service LIKE '%{0}%' COLLATE NOCASE".format(term)
        return self.cursor.execute(sql_command)

    def findn(self, term):
        sql_command = "SELECT * FROM services WHERE notes LIKE '%{0}%' COLLATE NOCASE".format(term)
        return self.cursor.execute(sql_command)

    def findid(self, id):
        sql_command = "SELECT * FROM services WHERE id = %s"%id
        return self.cursor.execute(sql_command)


class interpreter:
    def __init__(self):
        self.m = main()
        self.user = None
        self.password = None
        self.key = key("root", "Pasword")

    def results(self, results):
        if len(results) == 0:
            print(WARN + "No results")
            return

        while True:
            print(INFO + "\nindex     id  service")
            for i,j in enumerate(results):
                print(NORMAL + "%05s: %05s  %s"%(i, j[0], j[1]))

            sel = Input("Select number to view else hit Enter: ")
            try:
                v = int(sel.get())

                if (v > -1 and v < len(results)):
                    self.account(user=self.user)
                    try:
                        print(SUCCESS + "service: %s, email: %s, username: %s, password: %s%s%s, notes: %s"%(results[v][1],self.key.decrypt(results[v][2]),self.key.decrypt(results[v][3]), PASSWORD, self.key.decrypt(results[v][4]), SUCCESS, results[v][5]))
                        if iinput(NORMAL + "Edit (y/N): ").lower().strip() == "y":

                            values = list(results[v][1::])
                            values[1] = self.key.decrypt(values[1])
                            values[2] = self.key.decrypt(values[2])
                            values[3] = self.key.decrypt(values[3])
                            values = self.edit(values)

                            self.account(self.user, self.password)
                            print(SUCCESS + "Saving")
                            sql_command = "UPDATE services SET service=\"%s\", email=\"%s\", username=\"%s\", pass=\"%s\", notes=\"%s\" WHERE id=%s"%( values[0], self.key.encrypt(values[1]), self.key.encrypt(values[2]), self.key.encrypt(values[3]), values[4], results[v][0])
                            self.m.cursor.execute(sql_command)
                            self.m.comnection.commit()

                    except (cryptography.exceptions.InvalidSignature, cryptography.fernet.InvalidToken):
                        print(ERROR + "Bad user or password")
                        return

                    break
                else:
                    raise ValueError("Bad select value")
            except (ValueError,TypeError):
                if sel.raw.strip() == "":
                    print(SUCCESS + "Exiting")
                    return

    def account(self, user=None, password=None):
        self.user = iinput(NORMAL + "Enter user: ") if user == None else user
        self.password = iigetpass(NORMAL + "Enter master password for %s: "%self.user) if password == None else password

        self.key = key(self.user, self.password)
        return key

    def edit(self, values):
        values = list(values)
        while True:
            print(NORMAL + "\nCurrent data:\n0 service  :  %s\n1 email    :  %s\n2 username :  %s\n3 pass     :  %s\n4 note     :  %s\n"%(values[0], values[1], values[2], values[3], values[4]))

            sel = Input(NORMAL + "Select number to edit else hit Enter: ")
            try:
                v = int(sel.get())

                if (v > -1 and v < 5):
                    values[v] = iinput(NORMAL + "New value: ")
                else:
                    raise ValueError("Bad edit value")
            except (ValueError,TypeError) as e:
                if sel.raw.strip() == "":
                    break
        return values

    def start(self):
        print(INFO + "Commands:")
        print(NORMAL + " exit                      Exit Program")
        print(NORMAL + " acc                       Switch Account")
        print(NORMAL + " gen  <length default=32>  Generate password of length")
        print(NORMAL + " gens <length default=32>  Generate password of length with symbols")
        print(NORMAL + " id   <database id>        Get results based on database id")
        print(NORMAL + " s    <term>               Get results from matches in service column")
        print(NORMAL + " n    <term>               Get results from matches in notes column")
        print(NORMAL + " i                         Insert new values")
        while True:
            print()
            inp = Input(NORMAL + "%s $~ "%self.user)
            if inp.iscmd("exit"):
                break

            if inp.iscmd("id"):
                try:
                    v = int(inp.get(1))
                except (ValueError,TypeError):
                    pass
                else:
                    self.m.findid(v)

                    self.results(self.m.cursor.fetchall())
                    continue

            if inp.iscmd("acc"):
                self.account()

            if inp.iscmd("s"):
                term = inp.raw[1::].strip()
                print(INFO + "searching services for: %s"%term)
                self.m.finds(term)

                self.results(self.m.cursor.fetchall())
                continue

            if inp.iscmd("n"):
                term = inp.raw[1::].strip()
                print(INFO + "searching notes for: %s"%term)
                self.m.findn(term)

                self.results(self.m.cursor.fetchall())
                continue

            if inp.iscmd("gen"):
                random.seed(time.time())
                try:
                    v = int(inp.get(1))
                except (ValueError,TypeError):
                    v = 32

                out = [random.choice(string.ascii_letters + string.digits) for x in range(v)]
                print(NORMAL + "".join(out))

            if inp.iscmd("gens"):
                random.seed(time.time())
                try:
                    v = int(inp.get(1))
                except (ValueError,TypeError):
                    v = 32

                out = [random.choice(string.ascii_letters + string.digits + "!@#$%^&*()_-+=") for x in range(v)]
                print(NORMAL + "".join(out))

            if inp.iscmd("i"):
                print(INFO + "Leave blank is none:")
                values = [
                iinput(NORMAL + "Enter service: "),
                iinput(NORMAL + "Enter email: "),
                iinput(NORMAL + "Enter username: "),
                iinput(NORMAL + "Enter pass: "),
                iinput(NORMAL + "Enter note: ")
                ]

                values = self.edit(values)

                self.account(self.user, self.password)
                print(SUCCESS + "Saving")
                sql_command = "INSERT INTO services VALUES  (NULL, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\")"%( values[0], self.key.encrypt(values[1]), self.key.encrypt(values[2]), self.key.encrypt(values[3]), values[4])
                self.m.cursor.execute(sql_command)
                self.m.comnection.commit()


if __name__ == '__main__':

    i = interpreter()
    i.start()
