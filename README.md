# Prompt Filter Middleware

### 1 - Setup
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2 - Run
```bash
uvicorn app.main:app --reload
```

Service: http://127.0.0.1:8000
Swagger UI: http://127.0.0.1:8000/docs

### Running Tests

```bash
pytest -q
```

### Endpoints
###### GET /healthz

Service liveness check.

Sample output: { "ok": true, "version": "0.3.0" }

###### POST /moderate

Detect and classify the text.

Request body: application/json

