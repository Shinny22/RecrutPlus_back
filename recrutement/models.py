from django.db import models
from django.contrib.auth.models import AbstractUser


# -----------------------------
# Domaine
# -----------------------------
class Domaine(models.Model):
    id_dom = models.AutoField(primary_key=True)
    lib_dom = models.CharField(max_length=255)

    def __str__(self):
        return self.lib_dom

# -----------------------------
# Diplôme
# -----------------------------
class Diplome(models.Model):
    id_diplome = models.AutoField(primary_key=True)
    designation = models.CharField(max_length=255)
    domaine = models.ForeignKey(Domaine, on_delete=models.CASCADE, related_name="diplomes")

    def __str__(self):
        return self.designation

# -----------------------------
# Campagne
# -----------------------------
class Campagne(models.Model):
    cod_anne = models.CharField(max_length=20, primary_key=True)
    description = models.TextField()
    dat_debut = models.DateField()
    dat_fin = models.DateField()
    etat = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.cod_anne} - {self.description}"



# -----------------------------
# Candidat
# -----------------------------
class Candidat(models.Model):
    GENRE_CHOICES = [
        ("M", "Masculin"),
        ("F", "Féminin"),
    ]
    id_candidat = models.AutoField(primary_key=True)
    nom_cand = models.CharField(max_length=100)
    pren_cand = models.CharField(max_length=100)
    genre = models.CharField(max_length=1, choices=GENRE_CHOICES)
    dat_nais = models.DateField()
    lieu_nais = models.CharField(max_length=255)
    telephone1 = models.CharField(max_length=20)
    telephone2 = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(unique=True)
    photo = models.ImageField(upload_to="photos/", blank=True, null=True)
    sitmat = models.CharField(max_length=50, blank=True, null=True)  # Situation matrimoniale
    diplome = models.ForeignKey(Diplome, on_delete=models.SET_NULL, null=True, related_name="candidats")
    password = models.CharField(max_length=128,default="")

    def set_password(self, raw_password):
        self.password = make_password(raw_password)
        self.save()

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return f"{self.nom_cand} {self.pren_cand}"



from django.contrib.auth.hashers import make_password, check_password

class Compte(models.Model):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    candidat = models.OneToOneField(
        'Candidat',
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name='compte'
    )

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.email



# -----------------------------
# Demande
# -----------------------------
class Demande(models.Model):
    ETAT_CHOICES = [
        ("ENVOYEE", "Envoyée"),
        ("EN COURS", "En cours"),
        ("ACCEPTEE", "Acceptée"),
        ("REFUSEE", "Refusée"),
    ]

    id_dde = models.AutoField(primary_key=True)
    dat_dde = models.DateField(auto_now_add=True)
    cv = models.FileField(upload_to="cvs/")
    diplome_fichier = models.FileField(
    upload_to="diplomes/",
    blank=True,
    null=True,
    default="diplomes/default_diplome.pdf"
)  # ✅ fichier uploadé
    anne_obt_dip = models.PositiveSmallIntegerField()
    etat_dde = models.CharField(max_length=20, choices=ETAT_CHOICES, default="ENVOYEE")
    reponse = models.TextField(blank=True, null=True)
    campagne = models.ForeignKey(Campagne, on_delete=models.CASCADE, related_name="demandes")
    candidat = models.ForeignKey(Candidat, on_delete=models.CASCADE, related_name="demandes")

    def __str__(self):
        return f"Demande {self.id_dde} - {self.candidat.nom_cand}"


# models.py
class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    date_inscription = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.email


class ContactMessage(models.Model):
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100,blank=True,null=True)
    email = models.EmailField()
    message = models.TextField()
    date_envoi = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nom} - {self.email}"


from django.db import models

class CookieConsent(models.Model):
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE, null=True)
    consent_analytics = models.BooleanField(default=False)
    consent_marketing = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)