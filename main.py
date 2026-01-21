from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from controller import router as auth_router

app = FastAPI(
    title="Authentication API",
    description="API with user authentication using FastAPI and MongoDB",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include authentication router
app.include_router(auth_router)

@app.get("/")
async def root():
    return {
        "message": "Welcome to the Authentication API",
        "docs": "/docs",
        "health": "OK"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)