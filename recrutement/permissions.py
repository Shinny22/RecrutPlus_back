from rest_framework.permissions import SAFE_METHODS, BasePermission


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)


class ReadOnlyOrAdmin(BasePermission):
    """Lecture publique, écriture réservée aux administrateurs (JWT staff)."""

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_staff)


class AdminOnly(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_staff)
