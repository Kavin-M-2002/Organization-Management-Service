# Organization Management Service

A backend service for creating and managing organizations in a **multi-tenant architecture** using **FastAPI** and **MongoDB**.  
Each organization receives a **dynamically generated MongoDB collection**, while a master database stores global metadata and admin credentials.  
Authentication is implemented using **JWT**, and passwords are securely hashed.

This project was developed as part of a backend intern assignment.

---

# Table of Contents

1. [Features](#-features)  
2. [Technology Stack](#-technology-stack)  
3. [Project Structure](#-project-structure)  
4. [Setup Instructions](#-setup-instructions)  
   - [Clone Repository](#1-clone-repository)  
   - [Environment Variables](#2-environment-variables)  
   - [Run Using Docker (Recommended)](#3-run-using-docker-recommended)  
   - [Local Setup Without Docker](#4-run-locally-without-docker)  
5. [Running the Application](#-running-the-application)  
6. [API Endpoints](#-api-endpoints)  
7. [High-Level Architecture Diagram](#-high-level-architecture-diagram)  
8. [Design Notes](#-design-notes)  
9. [Push to GitHub](#-push-to-github)  
10. [License](#-license)

---

# Features

### ✔ Organization Management
- Create organization with a dedicated MongoDB collection (`org_<name>`)
- Get organization details
- Update organization name, email, password  
  → includes collection migration when renaming  
- Delete organization and its collection

### ✔ Admin Authentication
- Admin login using JWT
- Protected endpoints requiring authentication
- Passwords hashed with Argon2/bcrypt

---

# Technology Stack

| Component | Technology |
|----------|------------|
| Backend Framework | FastAPI |
| Database | MongoDB (Motor async driver) |
| Authentication | JWT (python-jose) |
| Password Hashing | Argon2 / bcrypt via Passlib |
| Containerization | Docker, Docker Compose |

1. Clone the Repository
git clone https://github.com/<your-username>/org-management-service.git
cd org-management-service

2. Create & Activate Virtual Environment (Optional but Recommended)
Create:
python -m venv .venv

Activate (Windows):
.venv\Scripts\activate

Activate (macOS/Linux):
source .venv/bin/activate

Install Dependencies
pip install -r requirements.txt

4. Create .env File

Create a new file named .env in the project root:

MONGO_URI=mongodb://localhost:27017
MASTER_DB=master_db
JWT_SECRET=your_strong_secret_here
ACCESS_TOKEN_EXPIRE_MINUTES=1440

5. Run the Application Locally

Start the FastAPI server:

uvicorn main:app --reload --host 0.0.0.0 --port 8000


Open Swagger UI:

http://localhost:8000/docs

6. Run Using Docker (Recommended)

Ensure Docker Desktop is running.

Build & start containers:
docker-compose up --build

Stop containers:
docker-compose down

Exposed services:
Service	URL	Description
FastAPI App	http://localhost:8000
	API Server
MongoDB	localhost:27017	Database backend
Running the Application

Once running (via Docker or uvicorn):

Access interactive documentation:
http://localhost:8000/docs

Test all API routes directly inside Swagger UI.

API Endpoints
1. Create Organization
POST /org/create

2. Get Organization
GET /org/get?organization_name=<name>

3. Update Organization
PUT /org/update

4. Delete Organization (Requires Authentication)
DELETE /org/delete

5. Admin Login
POST /admin/login


Returns JWT token.

Authentication Instructions
Step 1 — Login

Send:

POST /admin/login


Response example:

{
  "access_token": "<your-token>",
  "token_type": "bearer"
}

Step 2 — Click “Authorize” in Swagger UI

Enter:

Bearer <your-token>

Step 3 — You can now call protected routes

/org/update

/org/delete


Push to GitHub
git add .
git commit -m "Add project files"
git push origin main
