#?----------------------------------------------------------------- Modules -----------------------------------------------------------------#
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
from tkinter import *
import pyperclip
import sqlite3
import random
import sys

#*---------------------------------------------------------------- Functions  ---------------------------------------------------------------#
def getAllChildren(tree, item=""):
    children = tree.get_children(item)
    for child in children:
        children += getAllChildren(tree, child)
    return children

def copy(ent):
    pyperclip.copy(ent.get())

def updateFields(e):
    global currSno
    values = outputTreeView.item(outputTreeView.focus())['values']
    if values == "": return
    emailEnt.delete(0, END)
    usernameEnt.delete(0, END)
    passwordEnt.delete(0, END)
    remarksEnt.delete(0, END)
    currSno = values[0]
    emailEnt.insert(END, values[2])
    usernameEnt.insert(END, values[1])
    passwordEnt.insert(END, values[3])
    remarksEnt.insert(END, values[4])

def reloadTableSelDropDown():
    db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = db.fetchall()
    tableSelectDropDown['values'] = ("Create New", "-" * 200) + tuple(tables)
    
def reloadTreeView():
    global sno
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        return
    items = getAllChildren(outputTreeView)
    for item in items:
        outputTreeView.delete(item)
    db.execute(f"SELECT * FROM {currVal}")
    for i in db.fetchall():
        i = list(i)
        i[3] = f.decrypt(eval(i[3])).decode()
        outputTreeView.insert('', 'end', values=tuple(i))
        sno = int(i[0])
    sno += 1

def fixSnos():
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        return
    expectedSno = 1
    db.execute(f"SELECT * FROM {tableSelectDropDownVar.get()}")
    for value in db.fetchall():
        db.execute(f"DELETE FROM {tableSelectDropDownVar.get()} WHERE SNO='{value[0]}'")
        db.execute(f"INSERT INTO {tableSelectDropDownVar.get()} VALUES('{expectedSno}', '{value[1]}', '{value[2]}', \"{value[3]}\", '{value[4]}')")
        expectedSno += 1
    database.commit()
    reloadTreeView()

def closer():
    if messagebox.askyesno("Accounts Manager", "Are you sure you want to quit?"):
        root.destroy()

def dropDownSel(e):
    currVal = tableSelectDropDownVar.get()
    items = getAllChildren(outputTreeView)
    for item in items:
        outputTreeView.delete(item)
    if currVal == ("-"*200):
        tableSelectDropDownVar.set("Select...")
        reloadTableSelDropDown()
    elif currVal == "Create New":
        tableName = simpledialog.askstring("Accounts Manager", "Enter the table name")
        if tableName == None:
            tableSelectDropDownVar.set("Select...")
            clearFunc()
            return
        try:
            db.execute(f"CREATE TABLE \"{tableName}\"(SNO VARCHAR(3), EMAIL VARCHAR(100), USERNAME VARCHAR(30), PASSWORD VARCHAR(200), REMARKS VARCHAR(100))")
            reloadTableSelDropDown()
            tableSelectDropDownVar.set(tableName)
            reloadTreeView()
        except sqlite3.OperationalError:
            messagebox.showerror("Accounts Manager", "Invalid name for table")
            tableSelectDropDownVar.set("Select...")
    else:
        reloadTreeView()
    clearFunc()

def changeMasterPassFunc():
    iPassword = simpledialog.askstring("Accounts Manager", "Enter new Master Password")
    if iPassword == "" or iPassword.isspace():
        messagebox.showerror("Accounts Manager", "Please enter a password")
        return
    iPassword = f.encrypt(iPassword.encode())
    file = open("./files/masterPass", "w")
    file.seek(0)
    file.write(str(iPassword))
    file.close()

def genPassWindowCloser(w):
    w.destroy()
    passwordGenBtn.config(state="normal")

def generatePassword(strength, length, include, includePos, w, lbl):
    if strength == "" or strength.isspace():
        messagebox.showerror("Accounts Manager - Generate Password", "Please select a strength", parent=w)
        return
    if length == "" or length.isspace():
        messagebox.showerror("Accounts Manager - Generate Password", "Please enter a length", parent=w)
        return
    if include == "" or include.isspace():
        include = ""
        includePos = "S"
    if includePos == "" or includePos.isspace():
        messagebox.showerror("Accounts Manager - Generate Password", "Please select an include position", parent=w)
        return
    try:
        length = int(length)
    except ValueError:
        messagebox.showerror("Accounts Manager - Generate Password", "Please enter a numerical value for length", parent=w)
    password = ""
    if includePos == "S":
        password += include
    if strength == "Low":
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for i in range(0, length-len(include)):
            password += random.choice(characters)
    elif strength == "Medium":
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        for i in range(0, length-len(include)):
            password += random.choice(characters)
    elif strength == "High":
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890`~!@#$%^&*()-_=+[{]}:;|<,>.?/"
        for i in range(0, length-len(include)):
            password += random.choice(characters)
    if includePos == "E":
        password += include
    lbl.config(text=f"Output: {password}")

def gpInsert(lbl, w):
    password = lbl['text']
    password = password[8:]
    if password.isspace() or password == "":
        messagebox.showinfo("Accounts Manager - Generate Password", "Please Generate a Password")
        return
    passwordEnt.delete(0, END)
    passwordEnt.insert(END, password)
    genPassWindowCloser(w)

def generatePasswordFunc():
    passwordGenBtn.config(state="disabled")
    genPassWindow = Toplevel()
    genPassWindow.title("Accounts Manager - Generate Password")
    genPassWindow.geometry("400x400")
    genPassWindow.resizable(False, False)
    genPassWindow.focus_set()
    genPassWindow.protocol("WM_DELETE_WINDOW", lambda: genPassWindowCloser(genPassWindow))

    gpMainFrame = Frame(genPassWindow, bg=bg, bd=1, relief=GROOVE)
    gpMainFrame.place(relx=0, rely=0, relheight=1, relwidth=1)

    gpTitleLbl = Label(gpMainFrame, bg=mg, fg=fg, text="Generate Password", font=("Tahoma", 18))
    gpTitleLbl.place(relx=0, rely=0, relheight=0.2, relwidth=1)

    gpPasswordStrengthLbl = Label(gpMainFrame, bg=bg, fg=fg, text="Password Strength:", font=("Tahoma", 12))
    gpPasswordStrengthLbl.place(relx=0.075, rely=0.25)

    gpPasswordStrengthDropDownVar = StringVar()
    gpPasswordStrengthDropDownVar.set("Low")
    gpPasswordStrengthDropDown = ttk.Combobox(gpMainFrame, textvariable=gpPasswordStrengthDropDownVar, state="readonly", font=("Segoe UI", 12))
    gpPasswordStrengthDropDown['values'] = ("Low", "Medium", "High")
    gpPasswordStrengthDropDown.place(relx=0.075, rely=0.33, relwidth=0.85)

    gpPasswordLengthLbl = Label(gpMainFrame, bg=bg, fg=fg, text="Password Length:", font=("Tahoma", 12))
    gpPasswordLengthLbl.place(relx=0.075, rely=0.43)

    gpPasswordLengthEnt = Entry(gpMainFrame, bg=mg, fg=fg, bd=0, font=("Tahoma", 16))
    gpPasswordLengthEnt.place(relx=0.075, rely=0.51, relwidth=0.85)

    gpPasswordInclLbl = Label(gpMainFrame, bg=bg, fg=fg, text="Include characters:\t    |         Include Position:", font=("Tahoma", 12))
    gpPasswordInclLbl.place(relx=0.075, rely=0.61)
    
    gpPasswordInclEnt = Entry(gpMainFrame, bg=mg, fg=fg, bd=0, font=("Tahoma", 16))
    gpPasswordInclEnt.place(relx=0.075, rely=0.69, relwidth=0.415)

    gpPasswordPosVar = StringVar()
    gpPasswordPosVar.set("Select...")

    gpPasswordPos = ttk.Combobox(gpMainFrame, textvariable=gpPasswordPosVar, state="readonly", font=("Segoe UI", 12))
    gpPasswordPos["values"] = ("Start", "End")
    gpPasswordPos.place(relx=0.51, rely=0.69, relwidth=0.425)

    gpPasswordOLbl = Label(gpMainFrame, bg=bg, fg=fg, font=("Tahoma", 12))
    gpPasswordOLbl.place(relx=0.075, rely=0.8, relwidth=0.85)

    gpGenerateBtn = Button(gpMainFrame, bg=mg, fg=fg, text="Generate", font=("Tahoma", 12), bd=1, relief=GROOVE, command=lambda: generatePassword(gpPasswordStrengthDropDownVar.get(), gpPasswordLengthEnt.get(), gpPasswordInclEnt.get(), gpPasswordPosVar.get()[0], genPassWindow, gpPasswordOLbl))
    gpGenerateBtn.place(relx=0, rely=0.9, relheight=0.1, relwidth=0.5)

    gpInsertBtn = Button(gpMainFrame, bg=mg, fg=fg, text="Insert", font=("Tahoma", 12), bd=1, relief=GROOVE, command=lambda: gpInsert(gpPasswordOLbl, genPassWindow))
    gpInsertBtn.place(relx=0.5, rely=0.9, relheight=0.1, relwidth=0.5)

def addFunc():
    global sno
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        messagebox.showerror("Accounts Manager", "Please select a table to add")
        return
    email = usernameEnt.get()
    username = emailEnt.get()
    password = passwordEnt.get()
    remarks = remarksEnt.get()
    if email.isspace() or email == "":
        messagebox.showerror("Accounts Manager", "Please enter an email address")
        return
    if username.isspace() or username == "":
        messagebox.showerror("Accounts Manager", "Please enter an user name")
        return
    if password.isspace() or password == "":
        messagebox.showerror("Accounts Manager", "Please enter an password")
        return
    if remarks.isspace() or remarks == "":
        remarks = "None"
    db.execute(f"INSERT INTO {currVal} VALUES('{sno}', '{email}', '{username}', \"{f.encrypt(password.encode())}\", '{remarks}')")
    database.commit()
    fixSnos()
    reloadTreeView()
    messagebox.showinfo("Accounts manager", "Entry successfully added")
    clearFunc()

def updateFunc():
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        messagebox.showerror("Accounts Manager", "Please select a table to add")
        return
    email = emailEnt.get()
    username = usernameEnt.get()
    password = passwordEnt.get()
    remarks = remarksEnt.get()
    if currSno == -1:
        messagebox.showerror("Accounts Manager", "Please select an entry to update")
        return
    if email.isspace() or email == "":
        messagebox.showerror("Accounts Manager", "Please enter an email address")
        return
    if username.isspace() or username == "":
        messagebox.showerror("Accounts Manager", "Please enter an user name")
        return
    if password.isspace() or password == "":
        messagebox.showerror("Accounts Manager", "Please enter an password")
        return
    if remarks.isspace() or remarks == "":
        remarks = "None"
    db.execute(f"UPDATE {currVal} SET EMAIL='{username}', USERNAME='{email}', PASSWORD=\"{f.encrypt(password.encode())}\", REMARKS='{remarks}' WHERE SNO='{currSno}' ")
    database.commit()
    messagebox.showinfo("Accounts Manager", "Updated Successfully")
    reloadTreeView()
    clearFunc()

def searchFunc():
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        messagebox.showerror("Accounts Manager", "Please select a table to search")
        reloadTreeView()
        return
    username = emailEnt.get()
    email = usernameEnt.get()
    remarks = remarksEnt.get()

    if (email == "" or email.isspace()) and (username == "" or username.isspace()) and (remarks == "" or remarks.isspace()):
        messagebox.showerror("Accounts Manager", "Please enter Username, eMail and/or Remarks to search")
        reloadTreeView()
        return
    if (not (email == "" or email.isspace()) and not (username == "" or username.isspace()) and not (remarks == "" or remarks.isspace())): vals = 3
    elif ((not (email == "" or email.isspace()) and not (username == "" or username.isspace())) or (not (remarks == "" or remarks.isspace()) and not (username == "" or username.isspace())) or (not (remarks == "" or remarks.isspace()) and not (email == "" or email.isspace()))): vals = 2 
    elif (not (email == "" or email.isspace()) or not (username == "" or username.isspace()) or not (remarks == "" or remarks.isspace())): vals = 1
    if username == "" or username.isspace(): username = "JAqx9bVjCF2BQ0yMaGSLFVlihnZ0PraA1nz8S6UNXBBvZ-"
    if email == "" or email.isspace(): email = "JAqx9bVjCF2BQ0yMaGSLFVlihnZ0PraA1nz8S6UNXBBvZ-"
    if remarks  == "" or remarks.isspace(): remarks = "JAqx9bVjCF2BQ0yMaGSLFVlihnZ0PraA1nz8S6UNXBBvZ-"
    items = getAllChildren(outputTreeView)
    for item in items:
        outputTreeView.delete(item)
    db.execute(f"SELECT * FROM {currVal}")
    for val in db.fetchall():
        val = list(val)
        val[3] = f.decrypt(eval(val[3])).decode()
        val[4] = str(val[4])
        val = tuple(val)
        if vals == 3:
            if (val[1].find(email) != -1) and (val[2].find(username) != -1) and (val[4].find(remarks) != -1):
                outputTreeView.insert('', 'end', values=val)
        if vals == 2:
            if (val[1].find(email) != -1) and (val[2].find(username) != -1):
                outputTreeView.insert('', 'end', values=val)
            elif (val[1].find(email) != -1) and (val[4].find(remarks) != -1):
                outputTreeView.insert('', 'end', values=val)
            elif (val[2].find(username) != -1) and (val[4].find(remarks) != -1):
                outputTreeView.insert('', 'end', values=val)
        if vals == 1:
            if val[1].find(email) != -1:
                outputTreeView.insert('', 'end', values=val)
            elif val[2].find(username) != -1:
                outputTreeView.insert('', 'end', values=val)
            elif val[4].find(remarks) != -1:
                outputTreeView.insert('', 'end', values=val)

def deleteEntryFunc():
    currTable = tableSelectDropDownVar.get()
    try:
        currVal = outputTreeView.item(outputTreeView.selection()[0])['values']
    except IndexError:
        messagebox.showerror("Accounts Manager", "Please select an value before deleting")
        return
    if not messagebox.askyesno("Accounts Manager", "Are you sure you want to delete the selected value?"): return
    db.execute(f"DELETE FROM \"{currTable}\" WHERE SNO={currVal[0]}")
    database.commit()
    fixSnos()
    messagebox.showinfo("Accounts Manager", "Selected entry deleted successfully")
    reloadTreeView()
    clearFunc()

def deleteTableFunc():
    currVal = tableSelectDropDownVar.get()
    if currVal == "Select...":
        messagebox.showerror("Accounts Manager", "Please select a table to delete")
        return
    if not messagebox.askyesno("Accounts Manager", f"Are you sure you want to delete table {currVal}? This action is not reversible!"): return
    db.execute(f"DROP TABLE \"{currVal}\"")
    database.commit()
    messagebox.showinfo("Accounts Manager", f"Table {currVal} successfully deleted")
    reloadTableSelDropDown()
    tableSelectDropDownVar.set("Select...")
    items = getAllChildren(outputTreeView)
    for item in items:
        outputTreeView.delete(item)
    clearFunc()

def clearFunc():
    global currSno
    currSno = -1
    emailEnt.delete(0, END)
    usernameEnt.delete(0, END)
    passwordEnt.delete(0, END)
    remarksEnt.delete(0, END)
    try:
        outputTreeView.selection_remove(outputTreeView.selection()[0])
    except:
        pass

#!---------------------------------------------------------------- Variables ----------------------------------------------------------------#
key = b'fbCxyeAT3BnKZK7LoK-54Pc202AtcpJKXDc9vueTNGg='
f = Fernet(key)
currSno = -1
database = sqlite3.connect("./files/database.db")
db = database.cursor()
sno = 1

bg = "#6096BA"
mg = "#274C77"
fg = "#ffffff"
#? Orginal colours
#! bg = "#646464"
#! mg = "#7D7D7D"
#! fg = "#FFFFFF"

#!----------------------------------------------------------------- Window ------------------------------------------------------------------#
root = Tk()
root.withdraw()
iPassword = simpledialog.askstring("Accounts Manager", "Enter master password")
file1 = open("./files/masterPass", "r")
aPassword = eval(file1.read())
file1.close()
if not f.decrypt(aPassword).decode() == iPassword:
    messagebox.showinfo("Accounts Manager", "Master password incorrect")
    sys.exit()
root.deiconify()
root.title(" " * 175 + "Accounts Manager")
root.geometry("1366x780+0+0")
root.state("zoomed")
root.iconphoto(True, PhotoImage(file="./files/icon.png"))
root.protocol("WM_DELETE_WINDOW", closer)
root.minsize(1200,675)

mainFrame = Frame(root, bg=bg)
mainFrame.place(relx=0, rely=0, relwidth=1, relheight=1)

inputsFrame = Frame(root, bg=bg, bd=1, relief=GROOVE)
inputsFrame.place(relx=0, rely=0.1, relwidth=0.4, relheight=0.75)

treeViewFrame = Frame(root, bg=bg, bd=1, relief=GROOVE)
treeViewFrame.place(relx=0.4, rely=0.1, relwidth=0.6, relheight=0.75)

buttonsFrame = Frame(root, bg=bg, bd=1, relief=GROOVE)
buttonsFrame.place(relx=0, rely=0.85, relheight=0.15, relwidth=1)

titleLbl = Label(root, bg=mg, fg=fg, text="Accounts Manager", font=("Tahoma", 18), bd=2, relief=GROOVE)
titleLbl.place(relx=0, rely=0, relheight=0.1, relwidth=1)

inputsLabel = Label(inputsFrame, text="Inputs", bg=mg, fg=fg, font=("Tahoma", 18), bd=1, relief=GROOVE)
inputsLabel.place(relx=0, rely=0, relwidth=1, relheight=0.125)

usernameEntLbl = Label(inputsFrame, bg=bg, fg=fg, text="Email: ", font=("Segoe UI", 20))
usernameEntLbl.place(relx=0.05, rely=0.15)
usernameEnt = Entry(inputsFrame, bg=mg, fg=fg, font=("Segoe UI", 22), bd=0)
usernameEnt.place(relx=0.05, rely=0.24, relwidth=0.82, relheight=0.075)
usernameEntCopyBtn = Button(inputsFrame, bg=mg, fg=fg, bd=1, relief=GROOVE, font=("Segoe UI", 22), text="📋", command=lambda: copy(usernameEnt))
usernameEntCopyBtn.place(relx=0.87, rely=0.24, relheight=0.075, relwidth=0.08)

emailEntLbl = Label(inputsFrame, bg=bg, fg=fg, text="Username: ", font=("Segoe UI", 20))
emailEntLbl.place(relx=0.05, rely=0.36)
emailEnt = Entry(inputsFrame, bg=mg, fg=fg, font=("Segoe UI", 22), bd=0)
emailEnt.place(relx=0.05, rely=0.45, relwidth=0.82, relheight=0.075)
emailEntCopyBtn = Button(inputsFrame, bg=mg, fg=fg, bd=1, relief=GROOVE, font=("Segoe UI", 22), text="📋", command=lambda: copy(emailEnt))
emailEntCopyBtn.place(relx=0.87, rely=0.45, relheight=0.075, relwidth=0.08)

passwordEntLbl = Label(inputsFrame, bg=bg, fg=fg, text="Password: ", font=("Segoe UI", 20))
passwordEntLbl.place(relx=0.05, rely=0.57)
passwordEnt = Entry(inputsFrame, bg=mg, fg=fg, font=("Segoe UI", 22), bd=0)
passwordEnt.place(relx=0.05, rely=0.66, relwidth=0.82, relheight=0.075)
passwordEntCopyBtn = Button(inputsFrame, bg=mg, fg=fg, bd=1, relief=GROOVE, font=("Segoe UI", 22), text="📋", command=lambda: copy(passwordEnt))
passwordEntCopyBtn.place(relx=0.87, rely=0.66, relheight=0.075, relwidth=0.08)

remarksEntLbl = Label(inputsFrame, bg=bg, fg=fg, text="Remarks: ", font=("Segoe UI", 20))
remarksEntLbl.place(relx=0.05, rely=0.78)
remarksEnt = Entry(inputsFrame, bg=mg, fg=fg, font=("Segoe UI", 22), bd=0)
remarksEnt.place(relx=0.05, rely=0.87, relwidth=0.9, relheight=0.075)

tableSelectDropDownVar = StringVar()
tableSelectDropDownVar.set("Select...")
tableSelectDropDown = ttk.Combobox(treeViewFrame)
tableSelectDropDown.config(font=("Segoe UI", 12), textvariable=tableSelectDropDownVar, state="readonly")
tableSelectDropDown.bind("<<ComboboxSelected>>", dropDownSel)
tableSelectDropDown['values'] = ("Create New",)
tableSelectDropDown.place(relx=0, rely=0, relheight=0.05, relwidth=1)

outputTreeView = ttk.Treeview(treeViewFrame, columns=("c1", "c2", "c3", "c4", "c5"), show="headings")
outputTreeView.column("#1", anchor=CENTER, width=21)
outputTreeView.heading("#1", text="S.NO")
outputTreeView.column("#2", anchor=CENTER, width=300)
outputTreeView.heading("#2", text="Email Address")
outputTreeView.column("#3", anchor=CENTER, width=150)
outputTreeView.heading("#3", text="Username")
outputTreeView.column("#4", anchor=CENTER, width=150)
outputTreeView.heading("#4", text="Password")
outputTreeView.column("#5", anchor=CENTER, width=200)
outputTreeView.heading("#5", text="Remarks")
outputTreeView.bind("<ButtonRelease-1>", updateFields)
outputTreeView.place(relx=0, rely=0.05, relwidth=0.97, relheight=0.95)
outputTreeViewScrollBar = Scrollbar(treeViewFrame, orient="vertical", command=outputTreeView.yview)
outputTreeViewScrollBar.place(relx=0.97, rely=0.05, relwidth=0.03, relheight=0.95)

changeMasterPassBtn = Button(titleLbl, bg=mg, fg=fg, text="🔑", font=("Tahoma", 20), bd=1, relief=GROOVE, command=changeMasterPassFunc)
changeMasterPassBtn.place(relx=0, rely=0, relheight=1, relwidth=0.065)

passwordGenBtn = Button(titleLbl, bg=mg, fg=fg, text="🛠", font=("Tahoma", 20), bd=1, relief=GROOVE, command=generatePasswordFunc)
passwordGenBtn.place(relx=0.065, rely=0, relheight=1, relwidth=0.065)

refreshBtn = Button(titleLbl, bg=mg, fg=fg, text="⟳", font=("Tahoma", 20), bd=1, relief=GROOVE, command=fixSnos)
refreshBtn.place(relx=0.87, rely=0, relheight=1, relwidth=0.065)

closeBtn = Button(titleLbl, bg=mg, fg=fg, text="Ⓧ", font=("Tahoma", 20), bd=1, relief=GROOVE, command=closer)
closeBtn.place(relx=0.935, rely=0, relheight=1, relwidth=0.065)

addBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Add", font=("Tahoma", 20), bd=1, relief=GROOVE, command=addFunc)
addBtn.place(relx=0, rely=0, relheight=1, relwidth=0.2)

updateBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Update", font=("Tahoma", 20), bd=1, relief=GROOVE, command=updateFunc)
updateBtn.place(relx=0.2, rely=0, relheight=1, relwidth=0.2)

searchBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Search", font=("Tahoma", 20), bd=1, relief=GROOVE, command=searchFunc)
searchBtn.place(relx=0.4, rely=0, relheight=1, relwidth=0.2)

deleteEntBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Delete Entry", font=("Tahoma", 20), bd=1, relief=GROOVE, command=deleteEntryFunc)
deleteEntBtn.place(relx=0.6, rely=0, relheight=0.5, relwidth=0.2)

deleteTabBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Delete Table", font=("Tahoma", 20), bd=1, relief=GROOVE, command=deleteTableFunc)
deleteTabBtn.place(relx=0.6, rely=0.5, relheight=0.5, relwidth=0.2)

clearBtn = Button(buttonsFrame, bg=mg, fg=fg, text="Clear", font=("Tahoma", 20), bd=1, relief=GROOVE, command=clearFunc)
clearBtn.place(relx=0.8, rely=0, relheight=1, relwidth=0.2)

reloadTableSelDropDown()
root.mainloop()
database.close()
