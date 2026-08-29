# AegisDevSec

AI-powered DevSecOps automation platform — SAST, SCA, secrets scanning,
and LLM-based patch generation integrated with GitHub.

## Local Setup

1. Clone the repo:
   git clone https://github.com/coder28-cloud/aegis-ai-security.git
   cd aegis-ai-security

2. Copy the example env file and fill in real values:
   cp .env.example .env

3. Start Postgres and Redis:
   docker compose up -d postgres redis

4. Install backend dependencies:
   cd backend
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt

5. Run the test suite:
   pytest

6. Run the API locally:
   uvicorn app.main:app --reload

   API docs will be available at http://localhost:8000/docs