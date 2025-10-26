# recruteur/admin.py
from django.contrib import admin
from .models import *

@admin.register(Domaine)
class DomaineAdmin(admin.ModelAdmin):
    list_display = ('id_dom', 'lib_dom')


@admin.register(Diplome)
class DiplomeAdmin(admin.ModelAdmin):
    list_display = ('id_diplome', 'designation', 'domaine')


@admin.register(Campagne)
class CampagneAdmin(admin.ModelAdmin):
    list_display = ('cod_anne', 'description', 'dat_debut', 'dat_fin', 'etat')


@admin.register(Candidat)
class CandidatAdmin(admin.ModelAdmin):
    list_display = ('id_candidat', 'nom_cand', 'pren_cand', 'email', 'diplome', 'genre')


@admin.register(Demande)
class DemandeAdmin(admin.ModelAdmin):
    list_display = ('id_dde', 'candidat', 'campagne', 'dat_dde', 'etat_dde')

@admin.register(Compte)
class CompteAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'password', 'candidat')

@admin.register(Newsletter)
class NewsletterAdmin(admin.ModelAdmin):
    list_display = ('email', 'date_inscription')


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('nom', 'prenom', 'email', 'message', 'date_envoi')
