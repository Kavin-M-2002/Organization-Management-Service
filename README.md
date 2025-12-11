# Organization Management Service

A backend service for creating and managing organizations in a **multi-tenant architecture** using **FastAPI** and **MongoDB**.  
Each organization receives a **dynamically generated MongoDB collection**, while a master database stores global metadata and admin credentials.  
Authentication is implemented using **JWT**, and passwords are securely hashed.

This project was developed as part of a backend intern assignment.

---

# 📌 Table of Contents

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

# 🚀 Features

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

# 🧰 Technology Stack

| Component | Technology |
|----------|------------|
| Backend Framework | FastAPI |
| Database | MongoDB (Motor async driver) |
| Authentication | JWT (python-jose) |
| Password Hashing | Argon2 / bcrypt via Passlib |
| Containerization | Docker, Docker Compose |
