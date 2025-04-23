from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
import random, time, uuid, phonenumbers, hashlib
from datetime import datetime, timedelta

# إعداد قاعدة البيانات
DATABASE_URL = "sqlite:///./secure_chat.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# إعداد التطبيق
app = FastAPI()

# الجداول
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)  # UUID
    phone_number = Column(String, unique=True, index=True)
    session_id = Column(String)
    ip = Column(String)
    device_name = Column(String)

class OTP(Base):
    __tablename__ = "otps"
    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String)
    otp_code = Column(String)
    expiration_time = Column(Integer)
    attempts = Column(Integer, default=0)
    created_at = Column(Integer)

# إنشاء الجداول
Base.metadata.create_all(bind=engine)

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# البيانات الواردة
class OTPRequest(BaseModel):
    phone_number: str

class OTPVerify(BaseModel):
    phone_number: str
    otp_code: str
    ip: str
    device_name: str

# أدوات
def is_valid_number(phone: str) -> bool:
    try:
        parsed = phonenumbers.parse(phone, "IQ")
        return phonenumbers.is_valid_number(parsed)
    except:
        return False

# إرسال كود OTP
@app.post("/send_otp")
def send_otp(data: OTPRequest, db: Session = Depends(get_db)):
    if not is_valid_number(data.phone_number):
        raise HTTPException(status_code=400, detail="رقم الهاتف غير صالح")

    latest_otp = db.query(OTP).filter(OTP.phone_number == data.phone_number).order_by(OTP.id.desc()).first()
    now = int(time.time())

    # منع الإرسال المتكرر خلال 60 ثانية
    if latest_otp and now - latest_otp.created_at < 60:
        raise HTTPException(status_code=429, detail="يرجى الانتظار قبل طلب كود جديد")

    # حذف الأكواد السابقة
    db.query(OTP).filter(OTP.phone_number == data.phone_number).delete()

    otp_code = str(random.randint(1000, 9999))
    expiration = now + 300  # 5 دقائق
    db_otp = OTP(
        phone_number=data.phone_number,
        otp_code=otp_code,
        expiration_time=expiration,
        attempts=0,
        created_at=now
    )
    db.add(db_otp)
    db.commit()
    return {"message": f"تم إرسال كود (تجريبي): {otp_code}"}

# التحقق من OTP وتسجيل الدخول/إنشاء الحساب
@app.post("/verify_otp")
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    otp = db.query(OTP).filter(
        OTP.phone_number == data.phone_number
    ).order_by(OTP.id.desc()).first()

    if not otp:
        raise HTTPException(status_code=400, detail="لم يتم إرسال كود لهذا الرقم")
    
    now = int(time.time())
    if otp.expiration_time < now:
        db.delete(otp)
        db.commit()
        raise HTTPException(status_code=400, detail="انتهت صلاحية الكود")

    if otp.attempts >= 5:
        raise HTTPException(status_code=403, detail="تم تجاوز عدد المحاولات المسموح بها")

    if otp.otp_code != data.otp_code:
        otp.attempts += 1
        db.commit()
        raise HTTPException(status_code=400, detail="الكود غير صحيح")

    # حذف الكود بعد الاستخدام
    db.delete(otp)

    # تسجيل دخول أو إنشاء حساب
    user = db.query(User).filter(User.phone_number == data.phone_number).first()
    session_id = hashlib.sha256(f"{data.phone_number}{now}{uuid.uuid4()}".encode()).hexdigest()

    if user:
        user.session_id = session_id
        user.ip = data.ip
        user.device_name = data.device_name
    else:
        user = User(
            id=str(uuid.uuid4()),
            phone_number=data.phone_number,
            session_id=session_id,
            ip=data.ip,
            device_name=data.device_name
        )
        db.add(user)

    db.commit()
    return {
        "message": "تم الدخول بنجاح" if user else "تم إنشاء الحساب",
        "session_id": session_id,
        "user_id": user.id
    }
