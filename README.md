# Organization Management Service

A backend service for creating and managing organizations in a **multi-tenant architecture** using **FastAPI** and **MongoDB**. Each organization receives a **dynamically generated MongoDB collection**, while a master database stores global metadata and admin credentials. Authentication is implemented using **JWT**, and passwords are securely hashed.

# Features

### Organization Management
- Create organization with a dedicated MongoDB collection (`org_<name>`)
- Get organization details
- Update organization name, email, password  
  → includes collection migration when renaming  
- Delete organization and its collection

### Admin Authentication
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
```python -m venv .venv```

Activate (Windows):
```.venv\Scripts\activate```

Activate (macOS/Linux):
```source .venv/bin/activate```

Install Dependencies
```pip install -r requirements.txt```

4. Create .env File

Create a new file named .env in the project root:

```
MONGO_URI=mongodb://localhost:27017
MASTER_DB=master_db
JWT_SECRET=your_strong_secret_here
ACCESS_TOKEN_EXPIRE_MINUTES=1440
```

5. Run the Application Locally

Start the FastAPI server:

```uvicorn main:app --reload --host 0.0.0.0 --port 8000```


Open Swagger UI:

**http://localhost:8000/docs**

6. Run Using Docker (Recommended)

Ensure Docker Desktop is running.

Build & start containers:
```docker-compose up --build```

Stop containers:
```docker-compose down```

Exposed services:
Service	URL	Description
FastAPI App	**http://localhost:8000**
	API Server
MongoDB	**localhost:27017**	Database backend
Running the Application

Once running (via Docker or uvicorn):

Access interactive documentation:
**http://localhost:8000/docs**

Test all API routes directly inside Swagger UI.

API Endpoints
1. Create Organization
**POST /org/create**

2. Get Organization
**GET /org/get?organization_name=<name>**

3. Update Organization
**PUT /org/update**

4. Delete Organization (Requires Authentication)
**DELETE /org/delete**

5. Admin Login
**POST /admin/login**


Returns JWT token.

Authentication Instructions
Step 1 — Login

Send:

**POST /admin/login**


Response example:
```
{
  "access_token": "<your-token>",
  "token_type": "bearer"
}
```
Step 2 — Click “Authorize” in Swagger UI

Enter:

`Bearer <your-token>`

Step 3 — You can now call protected routes
```
/org/update

/org/delete
```

**Push to GitHub**
```
git add .
git commit -m "Add project files"
git push origin main
```

# Architecture Diagram
<img src="Architecture Diagram.png" alt="Alt text for the diagram" width="2500"/>

# Design Notes

## 1. Multi-Tenant Architecture Using Dynamic Collections

Instead of creating separate databases for each organization, the system uses one master database with dynamically created collections (org_<organization_name>).
This approach provides:

* Faster connection management

* Lower resource consumption

* Easier migrations and maintenance

* Simpler deployment on managed DB services like Atlas

* It also keeps each organization’s data logically isolated.

## 2. Master Database for Global Metadata

* A single master_db stores:

* Organization name

* Mapped collection name

* Admin credentials (hashed)

**Connection details**

This keeps all organizations discoverable without scanning multiple databases.
Lookups become lightweight and predictable.

## 3. Secure Authentication with JWT

`JWT` was selected because:

* It is stateless → no session store needed

* Easy to validate on each request

* Encodes both admin_id and organization_name for authorization

* This makes it suitable for scalable microservice-style backends.

## 4. Password Hashing with Argon2 / bcrypt

`Passwords` are hashed using Passlib, with either bcrypt or Argon2.
Reasons:

* Strong resistance to brute-force attacks

* Built-in salting

* Industry-standard practice for account security

* Plain passwords are never stored.

## 5. Async MongoDB Access Using Motor

`Motor` enables non-blocking database operations.
Benefits:

*Better performance under concurrency

*Ideal for FastAPI’s async request handlers

*This improves throughput for create/update/delete operations.

## 6. Collection Migration on Organization Rename

When renaming an organization:

* A new sanitized collection is created

* Documents from the old collection migrate to the new one

* Old collection is removed

* Master metadata updated

* This provides a smooth rename experience without data loss and demonstrates strong real-world multi-tenant behavior.

## 7. Dockerized Deployment for Simplicity

Using **Docker & Docker Compose**:

* Ensures consistent environments

* Removes OS-specific issues

* Simplifies onboarding for reviewers

* Allows `MongoDB` + `FastAPI` to run together effortlessly

This is ideal for assignment submissions and production deployment.

## 8. Clean, Modular Main File

Although the implementation is kept within main.py (as per assignment simplicity), the internal structure is still modular:

* Helpers for hashing, JWT, sanitization

* Separate request models

* Clear dependency injection for authentication

* Proper async database helpers

* This keeps the code easy to extend into a fully modular package later.

## 9. Error Handling & Validation

**FastAPI’s** validation ensures:

* Invalid inputs never reach the database

* Meaningful error messages

* Cleaner logic inside route handlers

* This reduces runtime issues and improves robustness.
