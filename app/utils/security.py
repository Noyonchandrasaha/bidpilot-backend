from __future__ import annotations
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4
import jwt
import redis.asyncio as redis
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
)
from pymongo import ReturnDocument
from motor.motor_asyncio import AsyncIOMotorDatabase
from passlib.context import CryptContext
from passlib.exc import InvalidHashError

from app.core.config import settings


from app.core.logger import logger


# =========================================================
# SECURITY EXCEPTIONS
# =========================================================

class SecurityError(Exception):
    """Base security exception."""


class InvalidCredentialsError(SecurityError):
    pass


class InvalidTokenTypeError(SecurityError):
    pass


class TokenExpiredError(SecurityError):
    pass


class TokenRevokedError(SecurityError):
    pass


class TokenReuseDetectedError(SecurityError):
    pass


class InvalidTokenClaimsError(SecurityError):
    pass


class InvalidSessionError(SecurityError):
    pass


class CSRFValidationError(SecurityError):
    pass


# =========================================================
# REDIS
# =========================================================

if settings.REDIS_URL:
    redis_client = redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
    )
else:
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD.get_secret_value() or None,
        ssl=settings.REDIS_SSL,
        decode_responses=True,
    )


# =========================================================
# SECURITY SERVICE
# =========================================================

class SecurityService:

    # =====================================================
    # JWT CONFIG
    # =====================================================

    ALGORITHM = "RS256"

    ACCESS_TOKEN_TYPE = "access"
    REFRESH_TOKEN_TYPE = "refresh"

    JWT_REQUIRED_CLAIMS = [
        "sub",
        "exp",
        "iat",
        "nbf",
        "iss",
        "aud",
        "jti",
        "type",
    ]

    JWT_LEEWAY_SECONDS = settings.JWT_LEEWAY_SECONDS

    ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS

    # =====================================================
    # PASSWORD HASHING
    # =====================================================

    pwd_context = CryptContext(
        schemes=["argon2"],
        deprecated="auto",

        argon2__memory_cost=65536,
        argon2__time_cost=3,
        argon2__parallelism=4,
        argon2__hash_len=32,
        argon2__salt_size=16,
    )

    # =====================================================
    # KEYS
    # =====================================================

    PRIVATE_KEYS = {
        settings.JWT_ACTIVE_KID:
            settings.JWT_PRIVATE_KEY.get_secret_value().strip(),
    }

    PUBLIC_KEYS = {
        settings.JWT_ACTIVE_KID:
            settings.JWT_PUBLIC_KEY.get_secret_value().strip(),
    }

    ACTIVE_KID = settings.JWT_ACTIVE_KID

    # =====================================================
    # PASSWORDS
    # =====================================================

    @classmethod
    def hash_password(cls, password: str) -> str:

        peppered = (
            f"{password}{settings.SECRET_PEPPER}"
        )

        return cls.pwd_context.hash(peppered)

    @classmethod
    def verify_password(
        cls,
        plain_password: str,
        hashed_password: str,
    ) -> bool:

        try:

            peppered = (
                f"{plain_password}"
                f"{settings.SECRET_PEPPER}"
            )

            return cls.pwd_context.verify(
                peppered,
                hashed_password,
            )

        except InvalidHashError:
            return False

    @classmethod
    def password_needs_rehash(
        cls,
        password_hash: str,
    ) -> bool:

        return cls.pwd_context.needs_update(
            password_hash
        )

    # =====================================================
    # TOKEN HASHING
    # =====================================================

    @classmethod
    def hash_token(cls, token: str) -> str:

        return hmac.new(
            settings.TOKEN_HASH_SECRET.get_secret_value().encode(),
            token.encode(),
            hashlib.sha256,
        ).hexdigest()

    # =====================================================
    # GENERIC TOKEN CREATION
    # =====================================================

    @classmethod
    def _create_token(
        cls,
        *,
        subject: str,
        token_type: str,
        expires_delta: timedelta,
        family_id: Optional[str] = None,
        session_id: Optional[str] = None,
        additional_claims: Optional[
            dict[str, Any]
        ] = None,
    ) -> tuple[str, str]:

        now = datetime.now(timezone.utc)

        jti = str(uuid4())

        payload = {
            "sub": subject,

            "jti": jti,
            "type": token_type,

            "iat": now,
            "nbf": now,
            "exp": now + expires_delta,

            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
        }

        if family_id:
            payload["family_id"] = family_id

        if session_id:
            payload["sid"] = session_id

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(
            payload,
            cls.PRIVATE_KEYS[cls.ACTIVE_KID],
            algorithm=cls.ALGORITHM,
            headers={
                "kid": cls.ACTIVE_KID,
            },
        )

        return token, jti

    # =====================================================
    # ACCESS TOKEN
    # =====================================================

    @classmethod
    def create_access_token(
        cls,
        *,
        user_id: str,
        session_id: str,
    ) -> str:

        token, _ = cls._create_token(
            subject=user_id,
            token_type=cls.ACCESS_TOKEN_TYPE,
            session_id=session_id,
            expires_delta=timedelta(
                minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES
            ),
        )

        return token

    # =====================================================
    # REFRESH TOKEN
    # =====================================================

    @classmethod
    async def create_refresh_token(
        cls,
        *,
        db: AsyncIOMotorDatabase,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[str, str]:

        family_id = str(uuid4())
        session_id = str(uuid4())

        token, jti = cls._create_token(
            subject=user_id,
            token_type=cls.REFRESH_TOKEN_TYPE,
            family_id=family_id,
            session_id=session_id,
            expires_delta=timedelta(
                days=cls.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )

        await db.refresh_sessions.insert_one({
            "session_id": session_id,

            "user_id": user_id,

            "family_id": family_id,

            "token_jti": jti,
            "token_hash": cls.hash_token(token),

            "revoked": False,
            "reused": False,

            "replaced_by": None,

            "ip_address": ip_address,
            "user_agent": user_agent,

            "created_at":
                datetime.now(timezone.utc),

            "last_used_at":
                datetime.now(timezone.utc),

            "expires_at":
                datetime.now(timezone.utc)
                + timedelta(
                    days=cls.REFRESH_TOKEN_EXPIRE_DAYS
                ),
        })

        logger.info(
            "refresh_token_created",
            extra={
                "user_id": user_id,
                "session_id": session_id,
            },
        )

        return token, session_id

    # =====================================================
    # TOKEN DECODING
    # =====================================================

    @classmethod
    def decode_token(
        cls,
        token: str,
    ) -> dict[str, Any]:

        try:

            header = jwt.get_unverified_header(
                token
            )

            kid = header.get("kid")

            if not kid:
                raise InvalidTokenClaimsError(
                    "Missing kid"
                )

            public_key = cls.PUBLIC_KEYS.get(kid)

            if not public_key:
                raise InvalidTokenClaimsError(
                    "Unknown signing key"
                )

            payload = jwt.decode(
                token,
                public_key,
                algorithms=[cls.ALGORITHM],
                audience=settings.JWT_AUDIENCE,
                issuer=settings.JWT_ISSUER,
                leeway=cls.JWT_LEEWAY_SECONDS,
                options={
                    "require":
                        cls.JWT_REQUIRED_CLAIMS
                },
            )

            return payload

        except ExpiredSignatureError:
            raise TokenExpiredError(
                "Token expired"
            )

        except (
            InvalidAudienceError,
            InvalidIssuerError,
            InvalidTokenError,
        ) as e:
            raise InvalidTokenClaimsError(
                str(e)
            )

    # =====================================================
    # ACCESS TOKEN VERIFICATION
    # =====================================================

    @classmethod
    async def verify_access_token(
        cls,
        token: str,
    ) -> dict[str, Any]:

        payload = cls.decode_token(token)

        if payload["type"] != (
            cls.ACCESS_TOKEN_TYPE
        ):
            raise InvalidTokenTypeError(
                "Invalid access token"
            )

        revoked = await redis_client.get(
            f"revoked:{payload['jti']}"
        )

        if revoked:
            raise TokenRevokedError(
                "Access token revoked"
            )

        return payload

    # =====================================================
    # REFRESH TOKEN VERIFICATION
    # =====================================================

    @classmethod
    async def verify_refresh_token(
        cls,
        *,
        db: AsyncIOMotorDatabase,
        token: str,
    ) -> dict[str, Any]:

        payload = cls.decode_token(token)

        if payload["type"] != (
            cls.REFRESH_TOKEN_TYPE
        ):
            raise InvalidTokenTypeError(
                "Invalid refresh token"
            )

        token_hash = cls.hash_token(token)

        session = (
            await db.refresh_sessions.find_one({
                "token_hash": token_hash,
            })
        )

        if not session:
            raise InvalidSessionError(
                "Refresh session not found"
            )

        if session["revoked"]:
            raise TokenRevokedError(
                "Refresh token revoked"
            )

        if session["reused"]:
            raise TokenReuseDetectedError(
                "Replay attack detected"
            )

        if session["user_id"] != payload["sub"]:
            raise InvalidSessionError(
                "Refresh token subject mismatch"
            )

        if session["session_id"] != payload.get("sid"):
            raise InvalidSessionError(
                "Refresh token session mismatch"
            )

        if session["family_id"] != payload.get("family_id"):
            raise InvalidSessionError(
                "Refresh token family mismatch"
            )

        return payload

    # =====================================================
    # REFRESH TOKEN ROTATION
    # =====================================================

    @classmethod
    async def rotate_refresh_token(
        cls,
        *,
        db: AsyncIOMotorDatabase,
        refresh_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[str, str]:

        payload = cls.decode_token(refresh_token)

        if payload["type"] != (
            cls.REFRESH_TOKEN_TYPE
        ):
            raise InvalidTokenTypeError()

        old_token_hash = cls.hash_token(
            refresh_token
        )

        old_session = (
            await db.refresh_sessions.find_one_and_update(
                {
                    "token_hash": old_token_hash,
                    "revoked": False,
                    "reused": False,
                    "replaced_by": None,
                },
                {
                    "$set": {
                        "last_used_at":
                            datetime.now(
                                timezone.utc
                            )
                    }
                },
                return_document=(
                    ReturnDocument.AFTER
                ),
            )
        )

        if not old_session:

            compromised = (
                await db.refresh_sessions.find_one({
                    "token_hash":
                        old_token_hash
                })
            )

            if compromised:

                await db.refresh_sessions.update_many(
                    {
                        "family_id":
                            compromised[
                                "family_id"
                            ]
                    },
                    {
                        "$set": {
                            "revoked": True,
                            "reused": True,
                        }
                    },
                )

                logger.warning(
                    "refresh_reuse_detected",
                    extra={
                        "family_id":
                            compromised[
                                "family_id"
                            ],
                        "user_id":
                            compromised[
                                "user_id"
                            ],
                    },
                )

                raise (
                    TokenReuseDetectedError(
                        "Replay attack detected"
                    )
                )

            raise InvalidSessionError()

        new_token, new_jti = cls._create_token(
            subject=old_session["user_id"],
            token_type=cls.REFRESH_TOKEN_TYPE,
            family_id=old_session[
                "family_id"
            ],
            session_id=old_session[
                "session_id"
            ],
            expires_delta=timedelta(
                days=cls.REFRESH_TOKEN_EXPIRE_DAYS
            ),
        )

        await db.refresh_sessions.insert_one({
            "session_id":
                old_session["session_id"],

            "user_id":
                old_session["user_id"],

            "family_id":
                old_session["family_id"],

            "token_jti": new_jti,

            "token_hash":
                cls.hash_token(new_token),

            "revoked": False,
            "reused": False,

            "replaced_by": None,

            "ip_address": ip_address,
            "user_agent": user_agent,

            "created_at":
                datetime.now(timezone.utc),

            "last_used_at":
                datetime.now(timezone.utc),

            "expires_at":
                datetime.now(timezone.utc)
                + timedelta(
                    days=cls.REFRESH_TOKEN_EXPIRE_DAYS
                ),
        })

        await db.refresh_sessions.update_one(
            {
                "_id": old_session["_id"]
            },
            {
                "$set": {
                    "replaced_by": new_jti,
                }
            },
        )

        access_token = cls.create_access_token(
            user_id=old_session["user_id"],
            session_id=old_session[
                "session_id"
            ],
        )

        logger.info(
            "refresh_rotated",
            extra={
                "user_id":
                    old_session["user_id"],
                "session_id":
                    old_session["session_id"],
            },
        )

        return access_token, new_token

    # =====================================================
    # TOKEN REVOCATION
    # =====================================================

    @classmethod
    async def revoke_access_token(
        cls,
        *,
        jti: str,
        expires_at: datetime,
    ) -> None:

        ttl = int(
            (
                expires_at
                - datetime.now(timezone.utc)
            ).total_seconds()
        )

        if ttl <= 0:
            return

        await redis_client.setex(
            f"revoked:{jti}",
            ttl,
            "1",
        )

    # =====================================================
    # REVOKE SESSION
    # =====================================================

    @classmethod
    async def revoke_session(
        cls,
        *,
        db: AsyncIOMotorDatabase,
        session_id: str,
    ) -> None:

        await db.refresh_sessions.update_many(
            {
                "session_id": session_id,
            },
            {
                "$set": {
                    "revoked": True,
                }
            },
        )

        logger.info(
            "session_revoked",
            extra={
                "session_id": session_id
            },
        )

    # =====================================================
    # REVOKE ALL USER SESSIONS
    # =====================================================

    @classmethod
    async def revoke_all_user_sessions(
        cls,
        *,
        db: AsyncIOMotorDatabase,
        user_id: str,
    ) -> None:

        await db.refresh_sessions.update_many(
            {
                "user_id": user_id,
            },
            {
                "$set": {
                    "revoked": True,
                }
            },
        )

        logger.warning(
            "all_sessions_revoked",
            extra={
                "user_id": user_id
            },
        )

    # =====================================================
    # CSRF TOKEN
    # =====================================================

    @classmethod
    def generate_csrf_token(cls) -> str:

        return str(uuid4())

    @classmethod
    def validate_csrf_token(
        cls,
        csrf_cookie: str,
        csrf_header: str,
    ) -> None:

        if not csrf_cookie:
            raise CSRFValidationError()

        if not csrf_header:
            raise CSRFValidationError()

        if not hmac.compare_digest(
            csrf_cookie,
            csrf_header,
        ):
            raise CSRFValidationError()


security_service = SecurityService()
