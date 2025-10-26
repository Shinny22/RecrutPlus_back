# recruteur/views.py
from rest_framework import viewsets
from .models import *
from .serializers import *
from rest_framework.views import APIView
from rest_framework import generics, permissions
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated



class DomaineViewSet(viewsets.ModelViewSet):
    queryset = Domaine.objects.all()
    serializer_class = DomaineSerializer


class DiplomeViewSet(viewsets.ModelViewSet):
    queryset = Diplome.objects.all()
    serializer_class = DiplomeSerializer


class CampagneViewSet(viewsets.ModelViewSet):
    queryset = Campagne.objects.all()
    serializer_class = CampagneSerializer


class CandidatViewSet(viewsets.ModelViewSet):
    queryset = Candidat.objects.all()
    serializer_class = CandidatSerializer


class DemandeViewSet(viewsets.ModelViewSet):
    queryset = Demande.objects.all()
    serializer_class = DemandeSerializer

#-----------------------Vue  d'authentification Admin -----------------------------------


from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "username et password sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=username, password=password)

        if user is None or not getattr(user, "is_staff", False):
            return Response({"error": "Identifiants invalides ou accès non autorisé"}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_staff": user.is_staff,
            }
        }, status=status.HTTP_200_OK)




from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_staff


# -------------------------
# Admin endpoints
# -------------------------
class DemandeListAdminView(APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        demandes = Demande.objects.all()
        serializer = DemandeSerializer(demandes, many=True)
        return Response(serializer.data)



#-----------------------Vue  d'affichage des campagnes publiques -----------------------------------
from rest_framework.decorators import api_view
from rest_framework.response import Response

@api_view(['GET'])
def campagnes_publiques(request):
    campagnes = Campagne.objects.all()
    serializer = CampagneSerializer(campagnes, many=True)
    return Response(serializer.data)


#-----------------------Vue  d'inscription des candidats -----------------------------------

from rest_framework.permissions import BasePermission

class IsCandidat(BasePermission):
    """
    Autorise uniquement les candidats à accéder à la vue
    """
    def has_permission(self, request, view):
        return hasattr(request.user, 'candidat_profile')  # si tu relies User à Candidat

    def has_object_permission(self, request, view, obj):
        # Vérifie que l’objet appartient bien au candidat
        return obj.candidat.id_candidat == request.user.candidat_profile.id_candidat



class CandidatCreateView(generics.CreateAPIView):
    queryset = Candidat.objects.all()
    serializer_class = CandidatSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response({"message": "Candidat créé avec succès", "candidat": serializer.data}, status=status.HTTP_201_CREATED)


#-----------------------Vue  d'authentification des candidats -----------------------------------


from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password, check_password


# class CandidatLoginView(APIView):
#     def post(self, request):
#         email = request.data.get("email")
#         password = request.data.get("password")

#         # Vérification si l'email existe
#         if not Candidat.objects.filter(email=email).exists():
#             return Response(
#                 {"message": "Ce candidat n'existe pas. Veuillez créer un compte."},
#                 status=status.HTTP_404_NOT_FOUND
#             )

#         try:
#             candidat = Candidat.objects.get(email=email)

#             # Vérification du mot de passe
#             if not candidat.check_password(password):
#                 return Response(
#                     {"message": "Mot de passe incorrect"},
#                     status=status.HTTP_401_UNAUTHORIZED
#                 )

#             # Génération des tokens JWT
#             refresh = RefreshToken.for_user(candidat)
#             return Response({
#                 "refresh": str(refresh),
#                 "access": str(refresh.access_token),
#                 "candidat": CandidatSerializer(candidat).data
#             })

#         except Candidat.DoesNotExist:
#             # Ce bloc ne sera normalement jamais atteint
#             return Response(
#                 {"message": "Erreur d'authentification"},
#                 status=status.HTTP_401_UNAUTHORIZED
#             )




#-----------------------Vue  d'envoi des demandes de postulation -----------------------------------


class PostulerCampagneView(generics.CreateAPIView):
    queryset = Demande.objects.all()
    serializer_class = DemandeSerializer
    permission_classes = [permissions.IsAuthenticated]  # le candidat doit être connecté

    def perform_create(self, serializer):
        # On associe automatiquement le candidat connecté à la demande
        serializer.save(candidat=self.request.user.candidat_profile)


#-----------------------Vue  d'envoi des demandes de postulation -----------------------------------

from django.core.exceptions import ObjectDoesNotExist

class PostulerView(APIView):
    def post(self, request):
        data = request.data

        # 1️⃣ Vérifier ou créer le candidat
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
            }
        )

        # Si le candidat existait, on peut mettre à jour certaines infos si nécessaire
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

        # 2️⃣ Récupérer la campagne
        try:
            campagne = Campagne.objects.get(cod_anne=data.get("campagne"))
        except ObjectDoesNotExist:
            return Response({"error": "Campagne non trouvée"}, status=status.HTTP_404_NOT_FOUND)

        # 3️⃣ Créer la demande
        demande = Demande.objects.create(
            candidat=candidat,
            campagne=campagne,
            cv=request.FILES.get("cv"),
            diplome=data.get("diplome"),
            anne_obt_dip=data.get("anne_obt_dip"),
        )

        return Response({"message": "Demande envoyée avec succès"}, status=status.HTTP_201_CREATED)


#-----------------------Vue  d'affichage des demandes de postulation -----------------------------------

class MesDemandesView(APIView):
    def get(self, request, email):
        try:
            candidat = Candidat.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({"error": "Candidat non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        demandes = candidat.demandes.all()  # relation related_name="demandes"
        result = [
            {
                "id_dde": d.id_dde,
                "campagne": d.campagne.description,
                "cv": d.cv.url if d.cv else None,
                "diplome": d.diplome,
                "anne_obt_dip": d.anne_obt_dip,
                "etat_dde": d.etat_dde,
                "reponse": d.reponse,
                "date": d.dat_dde,
            }
            for d in demandes
        ]
        return Response(result, status=status.HTTP_200_OK)


# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Candidat
from .serializers import CandidatSerializer

class CandidatRegisterView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ['nom_cand', 'pren_cand', 'email', 'password']

        # Vérification des champs obligatoires
        for field in required_fields:
            if field not in data:
                return Response({"error": f"{field} est requis"}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si l'email existe déjà
        if Candidat.objects.filter(email=data['email']).exists():
            return Response({"error": "Email déjà utilisé"}, status=status.HTTP_400_BAD_REQUEST)

        # Création du compte
        candidat = Candidat(
            nom_cand=data['nom_cand'],
            pren_cand=data['pren_cand'],
            email=data['email']
        )
        candidat.set_password(data['password'])
        candidat.save()

        serializer = CandidatSerializer(candidat)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Candidat, Diplome
from .serializers import CandidatSerializer
from django.contrib.auth.hashers import make_password, check_password

class CandidatRegisterView(APIView):
    def post(self, request):
        data = request.data

        # Tous les champs obligatoires
        required_fields = [
            'nom_cand', 'pren_cand', 'genre', 'dat_nais', 'lieu_nais',
            'telephone1', 'email', 'password'
        ]
        for field in required_fields:
            if field not in data:
                return Response({"error": f"{field} est requis"}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si l'email existe déjà
        if Candidat.objects.filter(email=data['email']).exists():
            return Response({"error": "Email déjà utilisé"}, status=status.HTTP_400_BAD_REQUEST)

        candidat = Candidat(
            nom_cand=data['nom_cand'],
            pren_cand=data['pren_cand'],
            genre=data['genre'],
            dat_nais=data['dat_nais'],
            lieu_nais=data['lieu_nais'],
            telephone1=data['telephone1'],
            telephone2=data.get('telephone2', None),
            email=data['email'],
            sitmat=data.get('sitmat', None),
            # diplome=diplome
        )
        candidat.set_password(data['password'])  # hash du mot de passe

        # Sauvegarde finale
        candidat.save()

        serializer = CandidatSerializer(candidat)
        return Response(serializer.data, status=status.HTTP_201_CREATED)



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Compte, Candidat
from .serializers import CompteSerializer, CandidatSerializer

class CompteRegisterView(APIView):
    def post(self, request):
        data = request.data
        required_fields = ['nom_cand', 'pren_cand', 'email', 'password']

        # Vérifier les champs obligatoires
        for field in required_fields:
            if field not in data:
                return Response({"error": f"{field} est requis"}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si l'email existe déjà
        if Compte.objects.filter(email=data['email']).exists():
            return Response({"error": "Email déjà utilisé"}, status=status.HTTP_400_BAD_REQUEST)

        # Créer le profil candidat
        candidat = Candidat(
            nom_cand=data['nom_cand'],
            pren_cand=data['pren_cand']
        )
        candidat.save()

        # Créer le compte lié au candidat
        compte = Compte(
            email=data['email'],
            candidat=candidat
        )
        compte.set_password(data['password'])
        compte.save()

        serializer = CompteSerializer(compte)
        return Response(serializer.data, status=status.HTTP_201_CREATED)






import jwt
from django.conf import settings
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Candidat
from .serializers import CandidatSerializer

class CandidatLoginView(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return Response({"error": "Email et mot de passe requis"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            candidat = Candidat.objects.get(email=email)
        except Candidat.DoesNotExist:
            return Response({"error": "Email ou mot de passe incorrect"}, status=status.HTTP_401_UNAUTHORIZED)

        if not candidat.check_password(password):
            return Response({"error": "Email ou mot de passe incorrect"}, status=status.HTTP_401_UNAUTHORIZED)

        # Création du token JWT
        payload = {
            "id": candidat.id_candidat,
            "exp": datetime.utcnow() + timedelta(hours=24),
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

        serializer = CandidatSerializer(candidat)
        return Response({"user": serializer.data, "token": token})



from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Candidat, Demande, Compte
from .serializers import CandidatSerializer, DemandeSerializer
from django.core.mail import send_mail

from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import check_password


# 🚪 Déconnexion
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Déconnexion réussie"}, status=205)
        except Exception:
            return Response({"error": "Token invalide"}, status=400)


# 📋 Voir les demandes / suivi du dossier
class CandidatDemandesView(generics.ListAPIView):
    serializer_class = DemandeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        candidat = getattr(user, "candidat", None)
        return Demande.objects.filter(candidat=candidat)
        

from django.conf import settings

# 📰 Newsletter (inscription simple)
class NewsletterView(APIView):
    # permission_classes = [AllowAny]  # Tout le monde peut s'inscrire

    def post(self, request):
        email = request.data.get('email')
       
        
        if not email:
            return Response({"error": "Email requis"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Vérifier si l'email est valide (optionnel)
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({"error": "Email invalide"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Enregistrer dans la base de données (optionnel)
        newsletter, created = Newsletter.objects.get_or_create(email=email)
        
        if not created:
            return Response({
                "message": "Vous êtes déjà inscrit à notre newsletter",
                "alert": "Cet email est déjà abonné à notre newsletter."
            }, status=status.HTTP_200_OK)
        
        # Message professionnel pour la newsletter CFI-CIRAS / CFI-Recrute
        email_subject = "🎯 Bienvenue dans la Newsletter CFI-Recrute - Votre Passerelle vers l'Excellence Professionnelle"
        
        email_message = """
Cher(e) Futur(e) Professionnel(le),

Nous sommes ravis de vous accueillir dans la communauté CFI-Recrute !

🌟 VOTRE INSCRIPTION EST CONFIRMÉE

Félicitations ! Vous venez de franchir la première étape vers de nouvelles opportunités professionnelles. En rejoignant notre newsletter, vous bénéficiez désormais d'un accès privilégié aux dernières actualités du Centre de Formation en Informatique du CIRAS.

📋 CE QUE VOUS RECEVREZ :

✅ Les dernières campagnes de recrutement en exclusivité
✅ Des conseils d'experts pour optimiser votre candidature  
✅ Les tendances du marché de l'emploi dans votre secteur
✅ Des témoignages inspirants de nos anciens candidats
✅ Les formations et certifications les plus demandées
✅ Des invitations à nos événements de networking

🚀 PROCHAINES ÉTAPES :

Notre équipe d'experts en recrutement travaille continuellement pour vous proposer les meilleures opportunités. Restez attentif(ve) à votre boîte mail - les prochaines campagnes arrivent bientôt !

💡 CONSEIL DE NOS EXPERTS :
"La préparation est la clé du succès. Tenez votre CV à jour et préparez-vous à saisir les opportunités dès qu'elles se présentent."

📞 BESOIN D'AIDE ?
Notre équipe support est à votre disposition pour toute question concernant votre parcours professionnel ou nos services.

Cordialement,

L'Équipe CFI-Recrute
Centre de Formation en Informatique du CIRAS - CFI-CIRAS

---
🌐 Suivez-nous sur nos réseaux sociaux pour ne rien manquer !
📧 Cette newsletter vous a été envoyée car vous vous êtes inscrit(e) sur notre plateforme CFI-Recrute.

© 2024 CFI-CIRAS - Tous droits réservés
        """
        
        # Envoyer l'email de confirmation avec le message professionnel SEULEMENT pour les nouveaux abonnés
        try:
            send_mail(
                email_subject,
                email_message,
                "shinnyoyere@gmail.com",
                [email],
                fail_silently=False,
            )
        except Exception as e:
            # Si l'envoi d'email échoue, on supprime l'inscription créée
            newsletter.delete()
            return Response({
                "error": "Erreur lors de l'envoi de l'email de confirmation. Veuillez réessayer."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       
        return Response({
            "message": "Inscription à la newsletter réussie ! Consultez votre boîte mail pour la confirmation.",
            "success": "Email de bienvenue envoyé avec succès."
        }, status=status.HTTP_201_CREATED)


class MesDemandesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        payload = request.auth.payload
        candidat_id = payload.get("candidat_id")

        if not candidat_id:
            return Response({"error": "Profil introuvable"}, status=404)

        demandes = Demande.objects.filter(candidat_id=candidat_id)
        serializer = DemandeSerializer(demandes, many=True)
        return Response(serializer.data)



# -----------------------------
# Newsletter ViewSet
# -----------------------------
from .models import Newsletter
class NewsletterViewSet(viewsets.ModelViewSet):
    queryset = Newsletter.objects.all()
    serializer_class = NewsletterSerializer

from rest_framework.decorators import action
# -----------------------------
# Contact Message ViewSet
# -----------------------------

class ContactMessageViewSet(viewsets.ModelViewSet):
    queryset = ContactMessage.objects.all()
    serializer_class = ContactMessageSerializer

    @action(detail=True, methods=['post'])
    def reply(self, request, pk=None):
        """Envoyer une réponse à un message"""
        message = self.get_object()
        subject = request.data.get('subject')
        body = request.data.get('message')
        if not subject or not body:
            return Response({'error': 'Sujet et message requis.'}, status=status.HTTP_400_BAD_REQUEST)

        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[message.email],
        )
        return Response({'success': 'Réponse envoyée avec succès.'})