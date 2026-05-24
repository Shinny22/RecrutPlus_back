"""Utilitaires JWT candidat (PyJWT, distinct de SimpleJWT admin)."""

from datetime import timedelta

import jwt
from django.conf import settings
from django.utils import timezone

CANDIDAT_JWT_ALGORITHM = "HS256"
CANDIDAT_TOKEN_LIFETIME = timedelta(hours=24)


def encode_candidat_token(candidat_id: int) -> str:
    payload = {
        "id": candidat_id,
        "candidat_id": candidat_id,
        "exp": timezone.now() + CANDIDAT_TOKEN_LIFETIME,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=CANDIDAT_JWT_ALGORITHM)


def decode_candidat_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[CANDIDAT_JWT_ALGORITHM])


def extract_bearer_token(request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip() or None


def get_candidat_id_from_request(request) -> int | None:
    token = extract_bearer_token(request)
    if not token:
        return None
    try:
        payload = decode_candidat_token(token)
    except jwt.PyJWTError:
        return None
    return payload.get("id") or payload.get("candidat_id")


def get_admin_user_from_request(request):
    """Retourne l'utilisateur staff si le Bearer est un JWT SimpleJWT valide."""
    from rest_framework_simplejwt.authentication import JWTAuthentication

    try:
        auth_result = JWTAuthentication().authenticate(request)
    except Exception:
        return None
    if not auth_result:
        return None
    user, _token = auth_result
    return user if user.is_staff else None
