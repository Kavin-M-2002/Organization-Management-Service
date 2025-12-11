# Organization Management Service

A backend service for managing organizations in a **multi-tenant architecture** using **FastAPI** and **MongoDB**.  
Each organization gets its **own dynamic collection**, while the **master database** stores global metadata and admin credentials.  
Authentication is handled via **JWT**, and passwords are securely hashed.

This project was completed as part of a backend internship assignment.

---

## Features

### Organization Management  
- Create organization (with dynamic MongoDB collection)  
- Get organization details  
- Update organization (name, admin credentials, migrate data to new collection)  
- Delete organization (collection + metadata removed)

### Secure Admin Authentication  
- Admin login (`/admin/login`)  
- JWT-based authentication  
- Protected routes for update/delete  
- Strong password hashing (Argon2 or bcrypt depending on configuration)

### Technology Stack  
- **FastAPI** (Python)  
- **MongoDB** (Motor async driver)  
- **JWT (python-jose)**  
- **Docker & Docker Compose**

---
## Project Structure

Since the solution is intentionally simple and kept in **one file (`main.py`)**, the layout is:
org_management_service/
├── main.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md

