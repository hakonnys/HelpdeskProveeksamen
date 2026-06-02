import sqlite3 #sqlite3 er databasen jeg skal bruke
import bcrypt #bcrypt er for å hashe passord
from pathlib import Path #pathlib er for å håndtere filstier
from typing import Literal #literal 

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "helpdesk.db"

print(DB_PATH. resolve())

app = FastAPI(title="Helpdesk")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    conn= sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
    )
    """)


    conn.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
        priority TEXT NOT NULL CHECK(priority IN ('low', 'medium', 'high')),
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


init_db()



class UserCreate(BaseModel):
    username: str
    password: str
    role: Literal["admin", "user"]


class UserLogin(BaseModel):
    username: str
    password: str

class TicketCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=1000)
    priority: Literal["low", "medium", "high"]
    user_id: int


class RegisterAdmin(BaseModel):
    username: str
    password: str
    hemmelig_kode: str



def hash_password(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, password_hash: str):
    return bcrypt.checkpw(password.encode(), password_hash.encode())



def require_admin(role: str):
    if role != "admin":
        raise HTTPException(status_code=403, detail="Kun admin har tilgang")



@app.post("/registeradmin")
def lag_admin(user: RegisterAdmin):

    if user.hemmelig_kode !="hakonerkul":
        raise HTTPException(status_code=403, detail="Feil hemmelig kode")

    conn = get_db()

    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (user.username, hash_password(user.password), "admin")
    )

    conn.commit()

    return {"message": "Admin-bruker opprettet"}





@app.post("/register")
def register(user: UserCreate):
    conn = get_db()

    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (user.username, hash_password(user.password), user.role)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Brukernavn finnes allerede")
    
    return {"message": "Bruker registrert"}







@app.post("/login")
def login(user: UserLogin):
    conn = get_db()

    db_user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (user.username,)
    ).fetchone()

    if not db_user:
        raise HTTPException(status_code=400, detail="Bruker finnes ikke")
    
    if not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Feil passord")
    
    return {
     "message": "Innlogging vellykket",
     "user_id": db_user["id"],
     "username": db_user["username"],
     "role": db_user["role"]
    }







@app.post("/tickets")
def create_ticket(ticket: TicketCreate):
    conn = get_db()

    conn.execute("""
        INSERT INTO tickets (title, description, status, priority, user_id)
        VALUES (?, ?, 'open', ?, ?)
    """, (ticket.title, ticket.description, ticket.priority, ticket.user_id))

    conn.commit()
    
    return {"message": "Ticket opprettet"}






@app.get("/tickets")
def get_tickets(role: str):
    require_admin(role)

    conn = get_db()

    rows = conn.execute("""
        SELECT tickets.*, users.username
        FROM tickets
        JOIN users ON tickets.user_id = users.id
    """).fetchall()

    return [dict(row) for row in rows]






@app.post("/tickets/close/{ticket_id}")
def close_ticket(ticket_id: int, role: str):
    require_admin(role)
    
    conn = get_db()

    conn.execute("""
        UPDATE tickets
        SET status = 'closed'
        WHERE id = ?
    """, (ticket_id,))

    conn.commit()

    return {"message": "Ticket lukket"}




@app.get("/mytickets/{user_id}")
def get_my_tickets(user_id: int):

    conn = get_db()

    rows = conn.execute("""
        SELECT * FROM tickets WHERE user_id = ?
        """, (user_id,)).fetchall()

    return [dict(row) for row in rows]




@app.delete("/tickets/{ticket_id}")
def delete_ticket(ticket_id: int, role: str):

    require_admin(role)

    conn = get_db()

    cursor = conn.execute(
        "DELETE FROM tickets WHERE id = ?",
        (ticket_id,)
    )

    conn.commit()

    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Ticket ikke funnet")

    return {"message": "Ticket slettet"}


