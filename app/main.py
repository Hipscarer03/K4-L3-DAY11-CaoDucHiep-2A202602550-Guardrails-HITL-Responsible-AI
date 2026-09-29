from fastapi import FastAPI, Response
from contextlib import asynccontextmanager

is_shutting_down = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    global is_shutting_down
    # Start up
    yield
    # Shutting down
    is_shutting_down = True

app = FastAPI(lifespan=lifespan)

@app.get("/health")
async def health_check(response: Response):
    global is_shutting_down
    if is_shutting_down:
        response.status_code = 503
        return {"status": "shutting_down"}
    return {
        "status": "ok",
        "service": "api",
        "version": "1.0.0"
    }
