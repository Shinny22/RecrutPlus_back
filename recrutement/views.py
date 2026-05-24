from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db.models import Count, Q
from django.db.models.functions import TruncMonth, TruncYear
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, status, viewsets
from rest_framework.decorators import (
    action,
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from .auth_utils import (
    encode_candidat_token,
    get_admin_user_from_request,
    get_candidat_id_from_request,
)
from .permissions import AdminOnly, IsAdminUser, ReadOnlyOrAdmin

from .models import (
    Campagne,
    Candidat,
    Compte,
    ContactMessage,
    Demande,
    Diplome,
    Domaine,
    Newsletter,
)
from .serializers import (
    CampagneSerializer,
    CandidatSerializer,
    CompteSerializer,
    ContactMessageSerializer,
    DemandeSerializer,
    DiplomeSerializer,
    DomaineSerializer,
    NewsletterSerializer,
)
from .utils.export_excel import export_model_to_excel


class AdminJWTViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]


# -----------------------
# Model viewsets
# -----------------------
class DomaineViewSet(AdminJWTViewSet):
    queryset = Domaine.objects.all()
    serializer_class = DomaineSerializer
    permission_classes = [ReadOnlyOrAdmin]


class DiplomeViewSet(AdminJWTViewSet):
    queryset = Diplome.objects.all()
    serializer_class = DiplomeSerializer
    permission_classes = [ReadOnlyOrAdmin]


class CampagneViewSet(AdminJWTViewSet):
    queryset = Campagne.objects.all()
    serializer_class = CampagneSerializer
    permission_classes = [ReadOnlyOrAdmin]


class CandidatViewSet(AdminJWTViewSet):
    queryset = Candidat.objects.all()
    serializer_class = CandidatSerializer
    permission_classes = [AdminOnly]


class DemandeViewSet(AdminJWTViewSet):
    queryset = Demande.objects.all()
    serializer_class = DemandeSerializer
    permission_classes = [AdminOnly]


class NewsletterViewSet(AdminJWTViewSet):
    queryset = Newsletter.objects.all()
    serializer_class = NewsletterSerializer
    permission_classes = [AdminOnly]


class ContactMessageViewSet(AdminJWTViewSet):
    queryset = ContactMessage.objects.all().order_by("-date_envoi")
    serializer_class = ContactMessageSerializer

    def get_permissions(self):
        if self.action == "create":
            return [AllowAny()]
        return [AdminOnly()]

    def create(self, request, *args, **kwargs):
        data = request.data
        nom = data.get("nom")
        prenom = data.get("prenom", "")
        email = data.get("email")
        message = data.get("message")

        if not nom or not email or not message:
            return Response(
                {"error": "Tous les champs requis doivent être remplis."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        contact_message = ContactMessage.objects.create(
            nom=nom,
            prenom=prenom,
            email=email,
            message=message,
        )

        try:
            send_mail(
                subject=f"Nouveau message de {nom}",
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[settings.DEFAULT_FROM_EMAIL],
            )
        except Exception as exc:
            # Log en console pour debug sans casser la création
            print(f"Erreur envoi mail: {exc}")

        serializer = self.get_serializer(contact_message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], permission_classes=[AdminOnly])
    def reply(self, request, pk=None):
        message_obj = self.get_object()
        subject = request.data.get("subject")
        body = request.data.get("message")

        if not subject or not body:
            return Response(
                {"error": "Sujet et message requis."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[message_obj.email],
        )
        return Response({"success": "Réponse envoyée avec succès."})


# -----------------------
# Authentification admin
# -----------------------
@method_decorator(csrf_exempt, name="dispatch")
class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "username et password sont requis"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = authenticate(request, username=username, password=password)
        if user is None:
            return Response(
                {"error": "Identifiants invalides"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_staff:
            return Response(
                {"error": "Accès réservé aux administrateurs"},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "is_active": user.is_active,
                    "is_staff": user.is_staff,
                    "is_superuser": user.is_superuser,
                    "last_login": user.last_login,
                    "date_joined": user.date_joined,
                },
            }
        )


class DemandeListAdminView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        demandes = Demande.objects.select_related("candidat", "campagne").all()
        serializer = DemandeSerializer(demandes, many=True)
        return Response(serializer.data)


class ExportExcelAdminView(APIView):
    """
    Export Excel réservé aux administrateurs (JWT admin + is_staff).
    GET /admin/export/<model_name>/?etat=...&campagne=...
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request, model_name):
        model_key = model_name.lower().strip()
        queryset = None

        if model_key == "demandes":
            queryset = Demande.objects.select_related("candidat", "campagne").all()
            etat = request.query_params.get("etat")
            campagne = request.query_params.get("campagne")
            if etat:
                queryset = queryset.filter(etat_dde__iexact=etat.strip())
            if campagne:
                queryset = queryset.filter(campagne__cod_anne__iexact=campagne.strip())

        response, error = export_model_to_excel(model_key, queryset=queryset)
        if error:
            status_code = (
                status.HTTP_404_NOT_FOUND
                if "Aucune donnée" in error
                else status.HTTP_400_BAD_REQUEST
            )
            return Response({"error": error}, status=status_code)
        return response


# -----------------------
# Campagnes publiques
# -----------------------
@api_view(["GET"])
def campagnes_publiques(request):
    campagnes = Campagne.objects.all()
    serializer = CampagneSerializer(campagnes, many=True)
    return Response(serializer.data)


@api_view(["GET"])
def search_campagne_api(request):
    query = request.GET.get("q", "").strip()
    campagnes = Campagne.objects.all()

    if query:
        campagnes = campagnes.filter(
            Q(cod_anne__icontains=query)
            | Q(description__icontains=query)
            | Q(etat__icontains=query)
        )

    serializer = CampagneSerializer(campagnes, many=True)
    return Response(serializer.data)


# -----------------------
# Inscription / auth candidats
# -----------------------
class CandidatCreateView(generics.CreateAPIView):
    queryset = Candidat.objects.all()
    serializer_class = CandidatSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(
            {"message": "Candidat créé avec succès", "candidat": serializer.data},
            status=status.HTTP_201_CREATED,
        )


class CandidatRegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        required_fields = [
            "nom_cand",
            "pren_cand",
            "genre",
            "dat_nais",
            "lieu_nais",
            "telephone1",
            "email",
            "password",
        ]
        for field in required_fields:
            if field not in data:
                return Response(
                    {"error": f"{field} est requis"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if Candidat.objects.filter(email=data["email"]).exists():
            return Response(
                {"error": "Email déjà utilisé"}, status=status.HTTP_400_BAD_REQUEST
            )

        candidat = Candidat(
            nom_cand=data["nom_cand"],
            pren_cand=data["pren_cand"],
            genre=data["genre"],
            dat_nais=data["dat_nais"],
            lieu_nais=data["lieu_nais"],
            telephone1=data["telephone1"],
            telephone2=data.get("telephone2"),
            email=data["email"],
            sitmat=data.get("sitmat"),
        )
        candidat.set_password(data["password"])
        candidat.save()

        serializer = CandidatSerializer(candidat)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CompteRegisterView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ["nom_cand", "pren_cand", "email", "password"]
        for field in required_fields:
            if field not in data:
                return Response(
                    {"error": f"{field} est requis"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if Compte.objects.filter(email=data["email"]).exists():
            return Response(
                {"error": "Email déjà utilisé"}, status=status.HTTP_400_BAD_REQUEST
            )

        candidat = Candidat(
            nom_cand=data["nom_cand"],
            pren_cand=data["pren_cand"],
        )
        candidat.save()

        compte = Compte(
            email=data["email"],
            candidat=candidat,
        )
        compte.set_password(data["password"])
        compte.save()

        serializer = CompteSerializer(compte)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CandidatLoginView(APIView):
    """Login candidat : JWT PyJWT custom (pas SimpleJWT)."""
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email et mot de passe requis"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            candidat = Candidat.objects.get(email=email)
        except Candidat.DoesNotExist:
            return Response(
                {"error": "Email ou mot de passe incorrect"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not candidat.check_password(password):
            return Response(
                {"error": "Email ou mot de passe incorrect"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        token = encode_candidat_token(candidat.id_candidat)

        serializer = CandidatSerializer(candidat)
        # Renvoyer le token sous plusieurs clés pour éviter les "undefined"
        # côté front (certains clients attendent access/accessToken).
        return Response(
            {
                "user": serializer.data,
                "token": token,
                "access": token,
                "accessToken": token,
                # Pas de refresh JWT custom ici, mais on garde la clé pour compat front.
                "refresh": None,
                "refreshToken": None,
            }
        )


class LogoutView(APIView):
    """Blacklist du refresh admin (SimpleJWT). Candidats : déconnexion côté client."""

    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"message": "Déconnexion réussie"}, status=status.HTTP_200_OK)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Déconnexion réussie"}, status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {"error": "Token invalide ou déjà expiré"},
                status=status.HTTP_400_BAD_REQUEST,
            )

class CandidatDemandesView(generics.ListAPIView):
    serializer_class = DemandeSerializer
    #permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        candidat = getattr(user, "candidat", None)
        return Demande.objects.select_related("campagne").filter(candidat=candidat)


class MesDemandesView(APIView):
    """
    Demandes par email : JWT candidat (email doit correspondre) ou admin staff.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request, email):
        email = email.strip().lower()
        candidat_id = get_candidat_id_from_request(request)
        admin_user = get_admin_user_from_request(request)

        if candidat_id:
            try:
                candidat = Candidat.objects.get(id_candidat=candidat_id)
            except Candidat.DoesNotExist:
                return Response({"error": "Candidat introuvable"}, status=status.HTTP_404_NOT_FOUND)
            if candidat.email.lower() != email:
                return Response(
                    {"error": "Accès non autorisé à ce profil"},
                    status=status.HTTP_403_FORBIDDEN,
                )
        elif admin_user:
            try:
                candidat = Candidat.objects.get(email__iexact=email)
            except Candidat.DoesNotExist:
                return Response({"error": "Candidat introuvable"}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(
                {"error": "Authentification requise"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        demandes = Demande.objects.select_related("campagne").filter(candidat=candidat)
        serializer = DemandeSerializer(demandes, many=True)
        return Response(serializer.data)


class CandidatProfileView(APIView):
    """
    Renvoie le profil complet du candidat connecté via le token JWT (login candidats).
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        candidat_id = get_candidat_id_from_request(request)
        if not candidat_id:
            return Response(
                {"error": "Token manquant ou invalide"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            candidat = Candidat.objects.get(id_candidat=candidat_id)
        except Candidat.DoesNotExist:
            return Response({"error": "Candidat introuvable"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CandidatSerializer(candidat)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MesCandidaturesView(APIView):
    """
    Retourne les demandes du candidat connecté ainsi que l'état de chacune.

    Cette vue s'appuie sur le token JWT retourné par `CandidatLoginView`
    (format "Bearer <token>"). Elle renvoie une liste des demandes avec
    les informations essentielles de la campagne et le statut courant.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        candidat_id = get_candidat_id_from_request(request)
        if not candidat_id:
            return Response(
                {"error": "Token manquant ou invalide"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            candidat = Candidat.objects.get(id_candidat=candidat_id)
        except Candidat.DoesNotExist:
            return Response({"error": "Candidat introuvable"}, status=status.HTTP_404_NOT_FOUND)

        demandes = (
            Demande.objects.select_related("campagne")
            .filter(candidat=candidat)
            .order_by("-dat_dde")
        )

        data = [
            {
                "id_dde": d.id_dde,
                "date_depot": d.dat_dde,
                "etat": d.etat_dde,
                "reponse": d.reponse,
                "campagne": {
                    "code": d.campagne.cod_anne,
                    "description": d.campagne.description,
                    "etat": d.campagne.etat,
                    "dat_debut": d.campagne.dat_debut,
                    "dat_fin": d.campagne.dat_fin,
                },
            }
            for d in demandes
        ]

        return Response({"candidat": candidat_id, "demandes": data}, status=status.HTTP_200_OK)


# -----------------------
# Postulation
# -----------------------
class PostulerView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        required = ["email", "campagne", "anne_obt_dip"]
        for field in required:
            if not data.get(field):
                return Response(
                    {"error": f"{field} est requis"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if not request.FILES.get("cv"):
            return Response(
                {"error": "Le CV est requis"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        candidat, created = Candidat.objects.get_or_create(
            email=data.get("email"),
            defaults={
                "nom_cand": data.get("nom_cand"),
                "pren_cand": data.get("pren_cand"),
                "genre": data.get("genre"),
                "dat_nais": data.get("dat_nais"),
                "lieu_nais": data.get("lieu_nais"),
                "telephone1": data.get("telephone1"),
                "telephone2": data.get("telephone2", ""),
                "sitmat": data.get("sitmat", ""),
                "photo": data.get("photo"),
            },
        )

        if not created:
            candidat.nom_cand = data.get("nom_cand", candidat.nom_cand)
            candidat.pren_cand = data.get("pren_cand", candidat.pren_cand)
            candidat.genre = data.get("genre", candidat.genre)
            candidat.dat_nais = data.get("dat_nais", candidat.dat_nais)
            candidat.lieu_nais = data.get("lieu_nais", candidat.lieu_nais)
            candidat.telephone1 = data.get("telephone1", candidat.telephone1)
            candidat.telephone2 = data.get("telephone2", candidat.telephone2)
            if "photo" in request.FILES:
                candidat.photo = request.FILES["photo"]
            candidat.save()

        try:
            campagne = Campagne.objects.get(cod_anne=data.get("campagne"))
        except Campagne.DoesNotExist:
            return Response({"error": "Campagne non trouvée"}, status=status.HTTP_404_NOT_FOUND)

        if Demande.objects.filter(candidat=candidat, campagne=campagne).exists():
            return Response(
                {"error": "Une demande existe déjà pour cette campagne"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        Demande.objects.create(
            candidat=candidat,
            campagne=campagne,
            cv=request.FILES["cv"],
            diplome_fichier=request.FILES.get("diplome"),
            anne_obt_dip=data.get("anne_obt_dip"),
        )

        return Response({"message": "Demande envoyée avec succès"}, status=status.HTTP_201_CREATED)


# -----------------------
# Newsletter
# -----------------------
class NewsletterView(APIView):
    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": "Email requis"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({"error": "Email invalide"}, status=status.HTTP_400_BAD_REQUEST)

        newsletter, created = Newsletter.objects.get_or_create(email=email)

        if not created:
            return Response(
                {
                    "message": "Vous êtes déjà inscrit à notre newsletter",
                    "alert": "Cet email est déjà abonné à notre newsletter.",
                },
                status=status.HTTP_200_OK,
            )

        email_subject = "Bienvenue dans la Newsletter CFI-Recrute"
        email_message = (
            "Cher(e) Futur(e) Professionnel(le),\n\n"
            "Votre inscription est confirmée. Vous recevrez désormais nos campagnes, conseils et actualités professionnelles.\n\n"
            "L'Équipe CFI-Recrute"
        )

        try:
            send_mail(
                email_subject,
                email_message,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
        except Exception:
            newsletter.delete()
            return Response(
                {"error": "Erreur lors de l'envoi de l'email de confirmation. Veuillez réessayer."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {
                "message": "Inscription à la newsletter réussie ! Consultez votre boîte mail pour la confirmation.",
                "success": "Email de bienvenue envoyé avec succès.",
            },
            status=status.HTTP_201_CREATED,
        )


# -----------------------
# Statistiques & listes
# -----------------------
@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def statistiques_globales(request):
    total_campagnes = Campagne.objects.count()
    total_candidats = Candidat.objects.count()
    total_diplomes = Diplome.objects.count()
    total_demandes = Demande.objects.count()
    total_domaines = Domaine.objects.count()

    campagnes_par_annee = (
        Campagne.objects.annotate(annee=TruncYear("dat_debut"))
        .values("annee")
        .annotate(total=Count("cod_anne"))
        .order_by("annee")
    )

    candidats_par_mois = (
        Candidat.objects.annotate(mois=TruncMonth("dat_nais"))
        .values("mois")
        .annotate(total=Count("id_candidat"))
        .order_by("mois")
    )

    demandes_par_mois = (
        Demande.objects.annotate(mois=TruncMonth("dat_dde"))
        .values("mois")
        .annotate(total=Count("id_dde"))
        .order_by("mois")
    )

    data = {
        "global": {
            "campagnes": total_campagnes,
            "candidats": total_candidats,
            "diplomes": total_diplomes,
            "demandes": total_demandes,
            "domaines": total_domaines,
        },
        "par_annee": list(campagnes_par_annee),
        "candidats_par_mois": list(candidats_par_mois),
        "demandes_par_mois": list(demandes_par_mois),
    }

    return Response(data)


@api_view(["GET"])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def liste_candidats(request):
    candidats = Candidat.objects.all()
    data = [
        {
            "id": c.id_candidat,
            "nom_complet": f"{c.nom_cand} {c.pren_cand}",
            "email": c.email,
        }
        for c in candidats
    ]
    return Response(data)


# -----------------------
# Cookies consentement
# -----------------------
@csrf_exempt
def set_cookie_consent(request):
    """Enregistre le consentement utilisateur (cookie + optionnellement en base)."""

    if request.method != "POST":
        return JsonResponse({"error": "Méthode non autorisée"}, status=405)

    consent = request.POST.get("consent") or request.GET.get("consent")
    if consent not in ("accept", "reject", "custom"):
        return JsonResponse({"error": "Valeur de consentement invalide"}, status=400)

    if request.user.is_authenticated:
        from .models import CookieConsent

        CookieConsent.objects.update_or_create(
            user=request.user,
            defaults={
                "consent_analytics": consent in ("accept", "custom"),
                "consent_marketing": consent == "accept",
            },
        )

    response = JsonResponse({"status": "ok", "consent": consent})
    response.set_cookie(
        key="cookie_consent",
        value=consent,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        samesite="Lax",
        secure=not settings.DEBUG,
    )
    return response
