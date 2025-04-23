from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
import random, time, hashlib

# إعداد قاعدة البيانات
DATABASE_URL = "sqlite:///./test.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# تعريف التطبيق
app = FastAPI()

# تعريف الجداول
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
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

# إنشاء الجداول إذا لم تكن موجودة
Base.metadata.create_all(bind=engine)

# إعداد الاتصال بقاعدة البيانات
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# نماذج البيانات
class OTPRequest(BaseModel):
    phone_number: str

class OTPVerify(BaseModel):
    phone_number: str
    otp_code: str
    ip: str
    device_name: str

# إرسال كود OTP
@app.post("/send_otp")
def send_otp(data: OTPRequest, db: Session = Depends(get_db)):
    otp_code = str(random.randint(1000, 9999))
    expiration = int(time.time()) + 300  # الكود صالح لمدة 5 دقائق
    db_otp = OTP(phone_number=data.phone_number, otp_code=otp_code, expiration_time=expiration)
    db.add(db_otp)
    db.commit()
    return {"message": f"تم إرسال كود OTP (تجريبي): {otp_code}"}

# التحقق من الكود وتسجيل الدخول أو إنشاء حساب
@app.post("/verify_otp")
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    otp = db.query(OTP).filter(
        OTP.phone_number == data.phone_number,
        OTP.otp_code == data.otp_code
    ).order_by(OTP.id.desc()).first()

    if not otp:
        raise HTTPException(status_code=400, detail="OTP غير صحيح")
    if otp.expiration_time < int(time.time()):
        raise HTTPException(status_code=400, detail="انتهت صلاحية الكود")

    # حذف الكود بعد الاستخدام
    db.delete(otp)

    # تسجيل الدخول أو إنشاء حساب
    user = db.query(User).filter(User.phone_number == data.phone_number).first()
    session_id = hashlib.sha256(f"{data.phone_number}{time.time()}".encode()).hexdigest()

    if user:
        user.session_id = session_id
        user.ip = data.ip
        user.device_name = data.device_name
    else:
        user = User(
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
