from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import uuid4
import hashlib
import hmac
import secrets

from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.schemas.auth.forget_password import (
    ForgotPasswordResponse,
    OTPVerificationResponse,
    ResendOTPResponse,
    UpdatePasswordResponse,
)
from app.core.config import settings
from app.core.logger import logger
from app.utils.security import security_service


class ForgotPasswordService:
    OTP_TTL_SECONDS = 300
    VERIFIED_TOKEN_TTL_SECONDS = 600
    RESEND_COOLDOWN_SECONDS = 60
    MAX_VERIFY_ATTEMPTS = 5

    @staticmethod
    def _otp_hash(reset_id: str, otp: str) -> str:
        secret = settings.token_hash_secret.encode()
        payload = f"{reset_id}:{otp}".encode()
        return hmac.new(secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _generate_otp() -> str:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return "".join(secrets.choice(alphabet) for _ in range(6))

    @staticmethod
    def _create_reset_token(*, user_id: str, reset_id: str) -> str:
        token, _ = security_service._create_token(
            subject=user_id,
            token_type="pwd_reset",
            expires_delta=timedelta(seconds=ForgotPasswordService.OTP_TTL_SECONDS),
            additional_claims={"rid": reset_id},
        )
        return token

    @staticmethod
    def _create_verified_reset_token(*, user_id: str, reset_id: str) -> str:
        token, _ = security_service._create_token(
            subject=user_id,
            token_type="pwd_reset_verified",
            expires_delta=timedelta(seconds=ForgotPasswordService.VERIFIED_TOKEN_TTL_SECONDS),
            additional_claims={"rid": reset_id},
        )
        return token

    @staticmethod
    def _decode_reset_token(token: str, expected_type: str) -> dict[str, Any]:
        try:
            payload = security_service.decode_token(token)
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired reset token")
        if payload.get("type") != expected_type:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        if not payload.get("rid"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid reset token payload")
        return payload

    @staticmethod
    async def request_reset(*, db: AsyncIOMotorDatabase, email: str) -> ForgotPasswordResponse:
        user = await db.users.find_one({"email": email.strip().lower(), "deleted_at": None})

        if not user:
            reset_id = str(uuid4())
            reset_token = ForgotPasswordService._create_reset_token(
                user_id=str(new_document_id()),
                reset_id=reset_id,
            )
            return ForgotPasswordResponse(
                reset_token=reset_token,
                expires_in=ForgotPasswordService.OTP_TTL_SECONDS,
                retry_after=ForgotPasswordService.RESEND_COOLDOWN_SECONDS,
                otp_sent=True,
            )

        user_id = str(user["_id"])
        reset_id = str(uuid4())
        otp = ForgotPasswordService._generate_otp()
        otp_hash = ForgotPasswordService._otp_hash(reset_id, otp)
        now = datetime.now(timezone.utc)

        await db.password_resets.insert_one({
            "_id": new_document_id(),
            "reset_id": reset_id,
            "user_id": to_object_id(user_id),
            "otp_hash": otp_hash,
            "attempts": 0,
            "resend_after": now + timedelta(seconds=ForgotPasswordService.RESEND_COOLDOWN_SECONDS),
            "verified": False,
            "created_at": now,
            "updated_at": now,
            "expires_at": now + timedelta(seconds=ForgotPasswordService.OTP_TTL_SECONDS),
        })

        if settings.is_development:
            logger.info("password_reset_otp_generated", extra={"email": email, "otp": otp, "reset_id": reset_id})
            print(f"[DEV OTP] reset_id={reset_id} otp={otp}")

        reset_token = ForgotPasswordService._create_reset_token(user_id=user_id, reset_id=reset_id)
        return ForgotPasswordResponse(reset_token=reset_token, expires_in=ForgotPasswordService.OTP_TTL_SECONDS, retry_after=ForgotPasswordService.RESEND_COOLDOWN_SECONDS, otp_sent=True)

    @staticmethod
    async def verify_otp(*, db: AsyncIOMotorDatabase, otp: str, reset_token: str) -> OTPVerificationResponse:
        payload = ForgotPasswordService._decode_reset_token(reset_token, "pwd_reset")
        reset_id = payload["rid"]

        record = await db.password_resets.find_one({"reset_id": reset_id})
        if not record or record.get("expires_at", datetime.min.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Reset session expired")

        attempts = int(record.get("attempts", 0))
        if attempts >= ForgotPasswordService.MAX_VERIFY_ATTEMPTS:
            await db.password_resets.delete_one({"reset_id": reset_id})
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Maximum OTP attempts exceeded")

        expected_hash = record.get("otp_hash", "")
        provided_hash = ForgotPasswordService._otp_hash(reset_id, otp)
        if not hmac.compare_digest(expected_hash, provided_hash):
            attempts += 1
            await db.password_resets.update_one(
                {"reset_id": reset_id},
                {"$set": {"attempts": attempts, "updated_at": datetime.now(timezone.utc)}},
            )
            remaining = max(0, ForgotPasswordService.MAX_VERIFY_ATTEMPTS - attempts)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid OTP. Remaining attempts: {remaining}")

        await db.password_resets.update_one(
            {"reset_id": reset_id},
            {
                "$set": {
                    "verified": True,
                    "updated_at": datetime.now(timezone.utc),
                    "expires_at": datetime.now(timezone.utc) + timedelta(seconds=ForgotPasswordService.VERIFIED_TOKEN_TTL_SECONDS),
                }
            },
        )
        verified_token = ForgotPasswordService._create_verified_reset_token(user_id=payload["sub"], reset_id=reset_id)

        remaining = max(0, ForgotPasswordService.MAX_VERIFY_ATTEMPTS - attempts)
        return OTPVerificationResponse(verified=True, verified_reset_token=verified_token, expires_in=ForgotPasswordService.VERIFIED_TOKEN_TTL_SECONDS, remaining_attempts=remaining)

    @staticmethod
    async def resend_otp(*, db: AsyncIOMotorDatabase, reset_token: str) -> ResendOTPResponse:
        payload = ForgotPasswordService._decode_reset_token(reset_token, "pwd_reset")
        reset_id = payload["rid"]

        record = await db.password_resets.find_one({"reset_id": reset_id})
        now = datetime.now(timezone.utc)
        if not record or record.get("expires_at", datetime.min.replace(tzinfo=timezone.utc)) <= now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Reset session expired")

        resend_after = record.get("resend_after", datetime.min.replace(tzinfo=timezone.utc))
        if now < resend_after:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Please wait before requesting another OTP")

        otp = ForgotPasswordService._generate_otp()
        await db.password_resets.update_one(
            {"reset_id": reset_id},
            {
                "$set": {
                    "otp_hash": ForgotPasswordService._otp_hash(reset_id, otp),
                    "attempts": 0,
                    "verified": False,
                    "resend_after": now + timedelta(seconds=ForgotPasswordService.RESEND_COOLDOWN_SECONDS),
                    "updated_at": now,
                    "expires_at": now + timedelta(seconds=ForgotPasswordService.OTP_TTL_SECONDS),
                }
            },
        )

        if settings.is_development:
            logger.info("password_reset_otp_resent", extra={"otp": otp, "reset_id": reset_id})
            print(f"[DEV OTP] reset_id={reset_id} otp={otp}")

        refreshed_token = ForgotPasswordService._create_reset_token(user_id=payload["sub"], reset_id=reset_id)
        return ResendOTPResponse(reset_token=refreshed_token, expires_in=ForgotPasswordService.OTP_TTL_SECONDS, retry_after=ForgotPasswordService.RESEND_COOLDOWN_SECONDS, otp_resent=True)

    @staticmethod
    async def update_password(*, db: AsyncIOMotorDatabase, verified_reset_token: str, new_password: str) -> UpdatePasswordResponse:
        payload = ForgotPasswordService._decode_reset_token(verified_reset_token, "pwd_reset_verified")
        reset_id = payload["rid"]

        record = await db.password_resets.find_one({"reset_id": reset_id})
        if (
            not record
            or not record.get("verified")
            or record.get("expires_at", datetime.min.replace(tzinfo=timezone.utc)) <= datetime.now(timezone.utc)
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Reset verification is not valid")

        user_id = payload["sub"]
        now = datetime.now(timezone.utc)
        result = await db.users.update_one(
            {"_id": to_object_id(user_id)},
            {"$set": {"password_hash": security_service.hash_password(new_password), "updated_at": now}},
        )
        if result.modified_count != 1:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Reset verification is not valid")
        await security_service.revoke_all_user_sessions(db=db, user_id=user_id)
        await db.password_resets.delete_one({"reset_id": reset_id})

        return UpdatePasswordResponse(password_updated=True, sessions_revoked=True, updated_at=now)


forgot_password_service = ForgotPasswordService()
