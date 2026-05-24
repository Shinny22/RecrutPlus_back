from django.contrib.auth.hashers import make_password
from rest_framework import serializers

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


class DomaineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domaine
        fields = "__all__"


class DiplomeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Diplome
        fields = "__all__"


class CampagneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Campagne
        fields = "__all__"


class DemandeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Demande
        fields = "__all__"


class CandidatSerializer(serializers.ModelSerializer):
    demandes = DemandeSerializer(many=True, read_only=True)
    diplome = DiplomeSerializer(read_only=True)
    diplome_id = serializers.PrimaryKeyRelatedField(
        queryset=Diplome.objects.all(),
        source="diplome",
        write_only=True,
        required=False,
        allow_null=True,
    )

    class Meta:
        model = Candidat
        fields = [
            "id_candidat",
            "nom_cand",
            "pren_cand",
            "genre",
            "dat_nais",
            "lieu_nais",
            "telephone1",
            "telephone2",
            "email",
            "photo",
            "sitmat",
            "diplome",
            "diplome_id",
            "password",
            "demandes",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        candidat = Candidat(**validated_data)
        if password:
            candidat.set_password(password)
        candidat.save()
        return candidat

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance


class CompteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Compte
        fields = ["id", "email", "password", "candidat"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        password = validated_data.pop("password")
        compte = Compte(**validated_data)
        compte.set_password(password)
        compte.save()
        return compte


class NewsletterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Newsletter
        fields = "__all__"


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = "__all__"
