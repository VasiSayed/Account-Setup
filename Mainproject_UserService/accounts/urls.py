from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ManualOnboardByUsernameAPIView,
    AutoOnboardByUsernameAPIView,
    TenantUserListCreateView,
    TenantUserRetrieveUpdateView,
    RefreshTokenView,
    OrgCreateView,
    CompanyListCreateView,
    CompanyDetailView,
    EntityCreateView,
    SiteCreateView,
    AssignSiteModulesView,
    SiteModulesListView,
    DepartmentListCreateView,
    DepartmentDetailView,
    RoleListCreateView,
    RoleDetailView,
    RoleModulePermissionListCreateView,
    RoleModulePermissionDetailView,
    AdminLoginView,
    LoginView,
    logout_view,
    BuildingViewSet,
    FloorViewSet,
    UnitViewSet,
    ProvisionTenantWithModulesAPIView,
    UserDatabaseByUsernameView,
        GlobalBuildingViewSet, GlobalFloorViewSet, GlobalUnitViewSet,UsersWithModulePermissionView
)
from .views_user_assign import CurrentTenantUserView

router = DefaultRouter()
router.register(r"buildings", BuildingViewSet, basename="building")
router.register(r"floors", FloorViewSet, basename="floor")
router.register(r"units", UnitViewSet, basename="unit")
router.register(r'global/buildings', GlobalBuildingViewSet, basename='global-buildings')
router.register(r'global/floors', GlobalFloorViewSet, basename='global-floors')
router.register(r'global/units', GlobalUnitViewSet, basename='global-units')


urlpatterns = [
    path("users/with-permission/<str:module_codes>/", UsersWithModulePermissionView.as_view()),
    path("users/with-permission/", UsersWithModulePermissionView.as_view()),

    path("manual-onboard/", ManualOnboardByUsernameAPIView.as_view()),
    path("logout/", logout_view, name="logout"),
    path("auto-onboard/", AutoOnboardByUsernameAPIView.as_view()),
    path("login/", LoginView.as_view(), name="tenant-login"),
    path("admin/login/", AdminLoginView.as_view()),     
    path("refresh/", RefreshTokenView.as_view(), name="token_refresh"),
    path("provision-with-modules/", ProvisionTenantWithModulesAPIView.as_view(), name="provision-with-modules"),

    path("organizations/", OrgCreateView.as_view()),

    path("companies/", CompanyListCreateView.as_view()),
    path("companies/<int:pk>/", CompanyDetailView.as_view()),    
    path("entities/", EntityCreateView.as_view()),

    path("sites/", SiteCreateView.as_view()),
    path("sites/modules/assign/", AssignSiteModulesView.as_view(), name="assign-site-modules"),
    path("site-modules/", SiteModulesListView.as_view(), name="site-modules"),
    path("site-modules/<int:site_id>/", SiteModulesListView.as_view(), name="site-modules-by-id"),

    path("departments/", DepartmentListCreateView.as_view(), name="tenant-dept-list-create"),
    path("departments/<int:pk>/", DepartmentDetailView.as_view(), name="tenant-dept-detail"),

    path("roles/", RoleListCreateView.as_view(), name="tenant-role-list-create"),
    path("roles/<int:pk>/", RoleDetailView.as_view(), name="tenant-role-detail"),

    path("role-module-perms/", RoleModulePermissionListCreateView.as_view(), name="tenant-rmp-list-create"),
    path("role-module-perms/<int:pk>/", RoleModulePermissionDetailView.as_view(), name="tenant-rmp-detail"),

    path("tenant/users/", TenantUserListCreateView.as_view(), name="tenant-user-list-create"),
    path("tenant/users/<int:pk>/", TenantUserRetrieveUpdateView.as_view(), name="tenant-user-retrieve-update"),

    path("master/user-dbs/by-username/<str:username>/", UserDatabaseByUsernameView.as_view()),
    path("tenant/me/", CurrentTenantUserView.as_view(), name="tenant-me"),
    
    path("", include(router.urls)),
]
