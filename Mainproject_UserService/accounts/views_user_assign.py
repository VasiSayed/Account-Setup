from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.authentication import JWTTenantAuthentication
from .serializers import UserCreateUpdateAssignSerializer 
class CurrentTenantUserView(APIView):
    """
    GET /api/tenant/me/
    Auth: Bearer <tenant access token>
    Returns the current tenant user (with department_info, role_info).
    """
    authentication_classes = [JWTTenantAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # JWTTenantAuthentication should attach the tenant User to request.user
        ser = UserCreateUpdateAssignSerializer(request.user)
        return Response(ser.data, status=200)
