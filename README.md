# Description

A Backend service to create and manage organizations in a multi-tenant style (dynamic collections per org). Built with FastAPI + Motor (MongoDB). Includes JWT admin authentication.

## Features
- Create organization with dynamic Mongo collection creation
- Admin user for each organization (hashed password)
- Admin login (JWT)
- Get / Update / Delete organization endpoints
- Dockerized (Dockerfile + docker-compose)

## Repo layout
(see detailed structure in project root)

## Quick start (development)
1. Clone repo
```bash
git clone https://github.com/<your-user>/<repo>.git

cd Organization_Management_Service

2. Create Virtual Environment
cp .env.example .env

3. Build and run docker compose
docker-compose up --build -d

docker logs -f org_app

4. Create org & login:

POST /org/create (body: organization_name, email, password)

POST /admin/login -> get access_token

Use Authorization: Bearer <token> for protected endpoints.

