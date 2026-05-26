import json
import os
import secrets
from datetime import date
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, status, Request, Form
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn
from dotenv import load_dotenv

# .env Datei laden
load_dotenv()

# 1. Konstanten und Verzeichnisse initialisieren
BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / os.getenv("USERS_FILE_PATH", "users.json")
DATA_DIR = BASE_DIR / os.getenv("DATA_DIR_PATH", "data")
DATA_DIR.mkdir(exist_ok=True)

# Templates initialisieren
templates = Jinja2Templates(directory="templates")

app = FastAPI(title="Screenity Backend")
security = HTTPBasic()

# 2. CORS-Einstellungen
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Hilfsfunktionen ---

def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, Exception):
        return {}

def save_users(users: dict):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4, ensure_ascii=False)

def authenticate(credentials: HTTPBasicCredentials = Depends(security)) -> dict:
    users = load_users()
    for user_id, user_info in users.items():
        if user_info.get("email") == credentials.username:
            # secrets.compare_digest schützt vor Timing-Attacks
            if secrets.compare_digest(user_info.get("password", ""), credentials.password):
                # Wir packen die user_id mit in das Dictionary für späteren Zugriff
                user_info["id"] = user_id
                return user_info
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Anmeldung fehlgeschlagen",
        headers={"WWW-Authenticate": "Basic"},
    )

def authenticate_admin(current_user: dict = Depends(authenticate)) -> dict:
    if not current_user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Zugriff verweigert: Administrator-Rechte erforderlich"
        )
    return current_user

# --- Endpunkte ---

# 4. Endpunkt: Daten vom Handy empfangen
@app.post("/report", status_code=status.HTTP_201_CREATED)
@app.post("/report/", status_code=status.HTTP_201_CREATED)
async def receive_report(request: Request):
    try:
        data = await request.json()
        device_id = data.get("device_id")
        report_date = data.get("report_date")
        
        if not device_id or not report_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Missing device_id or report_date"
            )
            
        file_path = DATA_DIR / f"{device_id}.json"
        
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                device_data = json.load(f)
        else:
            device_data = {
                "device_id": device_id, 
                "device_name": data.get("device_name", "Unbekanntes Gerät"), 
                "reports": {}
            }
        
        # Report hinzufügen oder updaten
        device_data["reports"][report_date] = {
            "total_screen_time_ms": data.get("total_screen_time_ms", 0),
            "apps": data.get("apps", []),
            "detailed_events": data.get("detailedEvents", [])
        }
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(device_data, f, indent=4, ensure_ascii=False)
            
        return {"status": "success"}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

# 5. Endpunkt: Zusammenfassung
@app.get("/summary")
@app.get("/summary/")
def get_summary(current_user: dict = Depends(authenticate)):
    summary = []
    today_str = date.today().isoformat()
    total_today_ms = 0
    total_all_ms = 0
    
    allowed_devices = current_user.get("devices", [])
    
    for device_id in allowed_devices:
        file_path = DATA_DIR / f"{device_id}.json"
        if not file_path.exists():
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            reports = data.get("reports", {})
            dev_total_ms = sum(r.get("total_screen_time_ms", 0) for r in reports.values())
            today_ms = reports.get(today_str, {}).get("total_screen_time_ms", 0)
            
            total_today_ms += today_ms
            total_all_ms += dev_total_ms
            
            summary.append({
                "device_id": device_id,
                "device_name": data.get("device_name", "Unbekannt"),
                "days_tracked": len(reports),
                "total_screen_time_hours": round(dev_total_ms / 3600000, 2),
                "today_ms": today_ms,
                "reports": reports
            })
        except Exception:
            continue 
            
    return {
        "user_name": current_user.get("name"),
        "devices": summary,
        "total_all_devices_hours": round(total_all_ms / 3600000, 2),
        "today_total_all_devices_ms": total_today_ms
    }

# 6. Geräte verwalten
@app.put("/device/{device_id}")
async def update_device(device_id: str, request: Request, current_user: dict = Depends(authenticate)):
    # Sicherheitscheck: Darf der User dieses Gerät überhaupt bearbeiten?
    if device_id not in current_user.get("devices", []) and not current_user.get("is_admin"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Nicht autorisiert für dieses Gerät")

    file_path = DATA_DIR / f"{device_id}.json"
    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gerät nicht gefunden")
        
    try:
        new_data = await request.json()
        with open(file_path, "r", encoding="utf-8") as f:
            device_data = json.load(f)
            
        if "device_name" in new_data:
            device_data["device_name"] = new_data["device_name"]
            
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(device_data, f, indent=4, ensure_ascii=False)
            
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@app.delete("/device/{device_id}")
def delete_device(device_id: str, current_user: dict = Depends(authenticate_admin)):
    # Nur Admins dürfen Geräte komplett aus dem System löschen
    file_path = DATA_DIR / f"{device_id}.json"
    if file_path.exists():
        file_path.unlink()
        return {"status": "success"}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gerät nicht gefunden")

# --- Admin Bereich ---

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, current_user: dict = Depends(authenticate_admin)):
    users = load_users()
    devices = []
    
    for f in DATA_DIR.glob("*.json"):
        try:
            with open(f, "r", encoding="utf-8") as file:
                devices.append(json.load(file))
        except Exception:
            continue
            
    return templates.TemplateResponse(
        name="admin.html", 
        context={
            "request": request,
            "users": users, 
            "devices": devices,
            "current_user": current_user
        }
    )

@app.post("/admin/assign-device")
async def assign_device(
    user_id: str = Form(...), 
    device_id: str = Form(...), 
    current_user: dict = Depends(authenticate_admin)
):
    users = load_users()
    if user_id in users:
        if "devices" not in users[user_id]:
            users[user_id]["devices"] = []
        
        if device_id not in users[user_id]["devices"]:
            users[user_id]["devices"].append(device_id)
            save_users(users)
            
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/admin/remove-device")
async def remove_device(
    user_id: str = Form(...), 
    device_id: str = Form(...), 
    current_user: dict = Depends(authenticate_admin)
):
    users = load_users()
    if user_id in users and device_id in users[user_id].get("devices", []):
        users[user_id]["devices"].remove(device_id)
        save_users(users)
        
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

if __name__ == "__main__":
    # Werte aus der .env mit Fallback-Standards auslesen
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=True)