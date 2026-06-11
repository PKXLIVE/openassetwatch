from fastapi import FastAPI

app = FastAPI(
    title="OpenAssetWatch API",
    description="Open-source family network asset intelligence platform.",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "name": "OpenAssetWatch",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
