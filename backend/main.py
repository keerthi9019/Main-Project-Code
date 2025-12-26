from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path
import joblib
import pickle
import json
import sys
import os
import logging
from datetime import datetime
import sqlite3
import aiosqlite
from jose import JWTError, jwt
from passlib.context import CryptContext
import numpy as np
from pydantic import BaseModel, EmailStr
import json
from dotenv import load_dotenv

# Add parent directory to path to import project.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from project import ImprovedFeatureExtractor

# Load environment variables
load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-at-least-32-chars-long")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
MODEL_DIR = Path(os.getenv("MODEL_DIR", "../trained_model"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./malware_scans.db")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class User(BaseModel):
    email: EmailStr
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

class ScanResult(BaseModel):
    filename: str
    file_type: str
    prediction: str
    confidence: float
    threat_level: str
    scan_date: str
    details: dict

# Initialize FastAPI app
app = FastAPI(
    title="Malware Detection API",
    description="API for detecting malicious files using ensemble ML models",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "X-Requested-With"],
    expose_headers=["Content-Disposition"],
    max_age=3600
)

# Mount static files
app.mount("/static", StaticFiles(directory=MODEL_DIR), name="static")

# Load ML models and artifacts
logger.info(f"Looking for model files in: {MODEL_DIR}")
logger.info(f"Current working directory: {os.getcwd()}")

if not os.path.exists(MODEL_DIR):
    logger.error(f"Model directory not found: {MODEL_DIR}")
    raise FileNotFoundError(f"Model directory not found: {MODEL_DIR}")

required_files = [
    'trained_models.pkl',
    'scaler.pkl',
    'feature_names.pkl',
    'feature_stats.pkl',
    'feature_importance.pkl'
]

# Check if all required files exist
for file in required_files:
    file_path = MODEL_DIR / file
    if not os.path.exists(file_path):
        logger.error(f"Required model file not found: {file}")
        raise FileNotFoundError(f"Required model file not found: {file}")
    else:
        logger.info(f"Found required file: {file}")

try:
    logger.info("Loading ML models and artifacts...")
    trained_models = joblib.load(MODEL_DIR / "trained_models.pkl")
    scaler = joblib.load(MODEL_DIR / "scaler.pkl")
    feature_names = joblib.load(MODEL_DIR / "feature_names.pkl")
    feature_stats = joblib.load(MODEL_DIR / "feature_stats.pkl")
    feature_importance = joblib.load(MODEL_DIR / "feature_importance.pkl")
    
    # Initialize feature extractor
    feature_extractor = ImprovedFeatureExtractor(feature_names, feature_stats)
    logger.info("Models and artifacts loaded successfully")
except Exception as e:
    logger.error(f"Error loading models: {str(e)}")
    try:
        logger.info("Attempting to load with pickle as fallback...")
        trained_models = pickle.load(open(MODEL_DIR / "trained_models.pkl", 'rb'))
        scaler = pickle.load(open(MODEL_DIR / "scaler.pkl", 'rb'))
        feature_names = pickle.load(open(MODEL_DIR / "feature_names.pkl", 'rb'))
        feature_stats = pickle.load(open(MODEL_DIR / "feature_stats.pkl", 'rb'))
        feature_importance = pickle.load(open(MODEL_DIR / "feature_importance.pkl", 'rb'))
        feature_extractor = ImprovedFeatureExtractor(feature_names, feature_stats)
        logger.info("Models loaded successfully using pickle")
    except Exception as e:
        logger.error(f"Critical error loading models with pickle: {str(e)}")
        raise

# Database initialization
async def init_db():
    async with aiosqlite.connect(DATABASE_URL.replace("sqlite:///", "")) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        await db.commit()

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    if email == os.getenv("DEMO_USER_EMAIL"):
        return UserInDB(
            email=email,
            hashed_password=get_password_hash(os.getenv("DEMO_USER_PASSWORD")),
            disabled=False
        )

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Endpoints
@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/predict")
async def predict_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    # Enhanced logging for file upload
    logger.info(f"{'='*60}\nFILE UPLOAD REQUEST")
    logger.info(f"Filename: {file.filename}")
    logger.info(f"Content-Type: {file.content_type}")
    logger.info(f"Headers: {dict(file.headers)}")
    logger.info(f"User: {current_user.email}")
    logger.info("="*60)
    
    try:
        # Validate file extension
        file_ext = os.path.splitext(file.filename)[1].lower()
        logger.info(f"File extension: {file_ext}")
        
        if file_ext not in ['.pdf', '.docx', '.doc', '.json']:
            logger.warning(f"Unsupported file type: {file_ext}")
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type. Only PDF, DOCX, DOC, and JSON files are supported."
            )

        # Read and validate file content
        try:
            content = await file.read()
            if not content:
                raise HTTPException(
                    status_code=400,
                    detail="Empty file uploaded. Please upload a valid file."
                )
        except Exception as e:
            logger.error(f"Error reading file {file.filename}: {str(e)}")
            raise HTTPException(
                status_code=400,
                detail="Failed to read the uploaded file. Please try again."
            )
        # Extract features based on file type
        if file_ext == '.pdf':
            logger.info("Extracting PDF features...")
            try:
                features_array, _ = feature_extractor.extract_pdf_features(content)
                logger.info("PDF features extracted successfully")
            except Exception as e:
                logger.error(f"Error extracting PDF features: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to analyze PDF file: {str(e)}"
                )
        elif file_ext in ['.docx', '.doc']:
            logger.info("Extracting DOCX features...")
            try:
                features_array, _ = feature_extractor.extract_docx_features(content)
                logger.info("DOCX features extracted successfully")
            except Exception as e:
                logger.error(f"Error extracting DOCX features: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to analyze DOCX file: {str(e)}"
                )
        elif file_ext == '.json':
            logger.info("Extracting JSON features...")
            try:
                features_array, _ = feature_extractor.extract_json_features(content)
                logger.info("JSON features extracted successfully")
            except Exception as e:
                logger.error(f"Error extracting JSON features: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to analyze JSON file: {str(e)}"
                )
        else:
            logger.warning(f"Unsupported file type attempted: {file_ext}")
            raise HTTPException(
                status_code=400,
                detail="Unsupported file type. Only PDF, DOCX, DOC, and JSON files are supported."
            )

        # Scale features
        features_scaled = scaler.transform(features_array)

        # Get predictions from all models
        rf_proba = trained_models['Random Forest'].predict_proba(features_scaled)[0]
        xgb_proba = trained_models['XGBoost'].predict_proba(features_scaled)[0]
        nn_proba = trained_models['Neural Network'].predict_proba(features_scaled)[0]

        # Ensemble prediction (weighted average)
        ensemble_proba = (0.4 * rf_proba + 0.4 * xgb_proba + 0.2 * nn_proba)
        prediction_idx = np.argmax(ensemble_proba)
        confidence = ensemble_proba[prediction_idx]

        # Determine prediction and threat level
        prediction = "MALICIOUS" if prediction_idx == 1 else "BENIGN"
        if prediction_idx == 0:
            threat_level = "SAFE"
        else:
            if confidence >= 0.95:
                threat_level = "CRITICAL"
            elif confidence >= 0.85:
                threat_level = "HIGH"
            elif confidence >= 0.70:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

        # Prepare result
        result = {
            "status": prediction,
            "confidence": float(confidence),
            "threat_level": threat_level,
            "details": {
                "filename": file.filename,
                "file_type": file_ext,
                "file_size_kb": len(content) / 1024,
                "scan_date": datetime.now().isoformat()
            },
            "rf_confidence": float(rf_proba[prediction_idx]),
            "xgb_confidence": float(xgb_proba[prediction_idx]),
            "nn_confidence": float(nn_proba[prediction_idx])
        }

        # Save scan result to database
        async with aiosqlite.connect(DATABASE_URL.replace("sqlite:///", "")) as db:
            await db.execute("""
                INSERT INTO scans (
                    filename, file_type, prediction, confidence,
                    threat_level, scan_date, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                file.filename, file_ext, prediction, confidence,
                threat_level, datetime.now().isoformat(),
                json.dumps(result)
            ))
            await db.commit()

        return result

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dashboard")
async def get_dashboard(current_user: User = Depends(get_current_user)):
    async with aiosqlite.connect(DATABASE_URL.replace("sqlite:///", "")) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total scans
        async with db.execute("SELECT COUNT(*) as total FROM scans") as cursor:
            total_scans = (await cursor.fetchone())["total"]

        # Get counts by prediction
        async with db.execute("""
            SELECT prediction, COUNT(*) as count 
            FROM scans 
            GROUP BY prediction
        """) as cursor:
            prediction_counts = {row["prediction"]: row["count"] for row in await cursor.fetchall()}

        # Get counts by threat level
        async with db.execute("""
            SELECT threat_level, COUNT(*) as count 
            FROM scans 
            GROUP BY threat_level
        """) as cursor:
            threat_level_counts = {row["threat_level"]: row["count"] for row in await cursor.fetchall()}

        # Get recent scans
        async with db.execute("""
            SELECT * FROM scans 
            ORDER BY scan_date DESC 
            LIMIT 10
        """) as cursor:
            recent_scans = [dict(row) for row in await cursor.fetchall()]
            for scan in recent_scans:
                scan["details"] = json.loads(scan["details"])

        return {
            "total_scans": total_scans,
            "prediction_counts": prediction_counts,
            "threat_level_counts": threat_level_counts,
            "recent_scans": recent_scans
        }

@app.get("/analysis")
async def get_analysis(current_user: User = Depends(get_current_user)):
    # Get feature importance
    top_features = []
    importance_indices = np.argsort(feature_importance)[-10:][::-1]
    for idx in importance_indices:
        top_features.append({
            "name": feature_names[idx],
            "importance": float(feature_importance[idx])
        })

    return {
        "model_accuracies": {
            "random_forest": 0.9920,  # Pre-calculated accuracy from model evaluation
            "xgboost": 0.9915,       # Pre-calculated accuracy from model evaluation
            "neural_network": 0.9850  # Pre-calculated accuracy from model evaluation
        },
        "top_features": top_features,
        "evaluation_image_url": "/static/model_evaluation.png"
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    await init_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)