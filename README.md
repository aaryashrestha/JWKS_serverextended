# JWKS Server (Project 2 – CSCE 3550)

This project implements a secure JSON Web Key Set (JWKS) server using SQLite to store private keys. It provides endpoints for issuing JWTs and serving valid public keys via JWKS. This server also implements protection against SQL injection attacks.

---

## Features

- SQLite-backed storage for RSA private keys  
- Automatic generation of:
  - One **expired** key (for testing invalid JWTs)
  - One **valid** key (for issuing current JWTs)
- Endpoints:
  - `POST /auth` – Issues a JWT signed with a valid key  
  - `POST /auth?expired=true` – Issues a JWT signed with an expired key  
  - `GET /.well-known/jwks.json` – Returns JWKS containing all **valid (non-expired)** keys

---

## Tech Stack

- **Language:** Python 3  
- **Framework:** Flask  
- **Database:** SQLite  
---

## Prerequisites
Make sure python is downloaded; you will need pip (Python's package manager) to install required dependencies.

  Installation & Setup
  
1. Clone the repo
   
2. Create a Virtual Environment

python -m venv venv
venv\Scripts\activate


3. Install Dependencies

pip install -r requirements.txt


4. Run the Server

    Ensure gradebot.exe is within the project directory

python app.py


5. Testing Endpoints

Get JWKS (Returns public keys in JSON Web Key Set format)

  curl http://localhost:8080/.well-known/jwks.json

Post Auth (Issues a JWT using a valid private key)

  curl -X POST http://localhost:8080/auth

Post Auth with Expired Key (Issues a JWT using an expired private key)

  curl -X POST "http://localhost:8080/auth?expired=true"

  

6. Run Tests

pytest test_app.py --cov=app --cov-report=term-missing

