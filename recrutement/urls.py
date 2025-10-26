# recruteur/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


router = DefaultRouter()
router.register(r'domaines', DomaineViewSet)
router.register(r'diplomes', DiplomeViewSet)
router.register(r'campagnes', CampagneViewSet)
router.register(r'candidats', CandidatViewSet)
# router.register(r'comptes', CompteViewSet)
router.register(r'demandes', DemandeViewSet)
router.register(r'newsletters', NewsletterViewSet)
router.register(r'contacts', ContactMessageViewSet)

urlpatterns = [
    path('api/', include(router.urls)),
    path("login/", CandidatLoginView.as_view(), name="candidat-login"),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("register/", CandidatRegisterView.as_view(), name="candidat-register"),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path('api/campagnes/', campagnes_publiques, name='campagnes_publiques'),
    path("postuler/", PostulerView.as_view(), name="postuler"),
    path("mes-demandes/<str:email>/", MesDemandesView.as_view(), name="mes-demandes"),
    path("admin/demandes/", DemandeListAdminView.as_view(), name="admin-demandes"),
    path('candidat/demandes/', MesDemandesView.as_view(), name='mes_demandes'),
    path('candidat/newsletter/', NewsletterView.as_view(), name='newsletter'),
    path('contact-message/<int:pk>/reply/', ContactMessageViewSet.as_view({'post': 'reply'}), name='contact-message-reply'),
     path("admin/login/", AdminLoginView.as_view(), name="admin-login"),
    
]

