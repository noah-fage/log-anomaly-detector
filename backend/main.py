from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os

from analyzer import analyze_logs, predict_next_moves

load_dotenv()

app = FastAPI(title="Log Anomaly Detector", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://log-anomaly-detector-five.vercel.app", "https://sentinel-anomaly.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    log_text: str


class PredictRequest(BaseModel):
    anomalies: list


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
    if not request.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text cannot be empty")

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")

    result = await analyze_logs(request.log_text, api_key)
    return result


@app.post("/predict")
async def predict(request: PredictRequest):
    if not request.anomalies:
        raise HTTPException(status_code=400, detail="anomalies cannot be empty")

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")

    result = await predict_next_moves(request.anomalies, api_key)
    return result
