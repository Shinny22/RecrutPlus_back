# recruteur/serializers.py
from rest_framework import serializers
from .models import *
from django.contrib.auth.models import User

class DomaineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domaine
        fields = '__all__'


class DiplomeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Diplome
        fields = '__all__'


class CampagneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campagne
        fields = '__all__'


class CandidatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Candidat
        fields = '__all__'

from rest_framework import serializers
from .models import Compte

class CompteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Compte
        fields = ['id', 'email', 'password', 'candidat']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        compte = Compte(**validated_data)
        compte.set_password(validated_data['password'])
        compte.save()
        return compte




class DemandeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Demande
        fields = '__all__'




class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    nom_cand = serializers.CharField()
    pren_cand = serializers.CharField()
    genre = serializers.CharField()
    dat_nais = serializers.DateField()
    lieu_nais = serializers.CharField()
    telephone1 = serializers.CharField()
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ["email", "password", "nom_cand", "pren_cand", "genre", "dat_nais", "lieu_nais", "telephone1"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User.objects.create(email=validated_data["email"])
        user.set_password(password)
        user.save()

        # créer aussi le candidat lié
        Candidat.objects.create(
            user=user,
            nom_cand=validated_data["nom_cand"],
            pren_cand=validated_data["pren_cand"],
            genre=validated_data["genre"],
            dat_nais=validated_data["dat_nais"],
            lieu_nais=validated_data["lieu_nais"],
            telephone1=validated_data["telephone1"],
        )

        return user


class NewsletterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Newsletter
        fields = '__all__'


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = '__all__'