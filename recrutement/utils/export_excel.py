from datetime import datetime

import pandas as pd
from django.http import HttpResponse

from recrutement.models import (
    Campagne,
    Candidat,
    ContactMessage,
    Demande,
    Diplome,
    Domaine,
    Newsletter,
)

EXPORTABLE_MODELS = {
    "domaines",
    "diplomes",
    "campagnes",
    "candidats",
    "demandes",
    "newsletters",
    "contact-message",
}


def _file_label(file_field):
    if not file_field:
        return ""
    return file_field.name or str(file_field)


def _rows_for_domaines():
    return [
        {"ID": d.id_dom, "Libellé": d.lib_dom}
        for d in Domaine.objects.all().order_by("id_dom")
    ]


def _rows_for_diplomes():
    return [
        {
            "ID": d.id_diplome,
            "Désignation": d.designation,
            "Domaine": d.domaine.lib_dom if d.domaine_id else "",
        }
        for d in Diplome.objects.select_related("domaine").all().order_by("id_diplome")
    ]


def _rows_for_campagnes():
    return [
        {
            "Code année": c.cod_anne,
            "Description": c.description,
            "Date début": c.dat_debut,
            "Date fin": c.dat_fin,
            "État": c.etat,
        }
        for c in Campagne.objects.all().order_by("cod_anne")
    ]


def _rows_for_candidats():
    return [
        {
            "ID": c.id_candidat,
            "Nom": c.nom_cand,
            "Prénom": c.pren_cand,
            "Genre": c.get_genre_display(),
            "Date naissance": c.dat_nais,
            "Lieu naissance": c.lieu_nais,
            "Téléphone 1": c.telephone1,
            "Téléphone 2": c.telephone2 or "",
            "Email": c.email,
            "Situation matrimoniale": c.sitmat or "",
            "Diplôme": c.diplome.designation if c.diplome_id else "",
            "Photo": _file_label(c.photo),
        }
        for c in Candidat.objects.select_related("diplome").all().order_by("id_candidat")
    ]


def _rows_for_demandes(queryset=None):
    qs = queryset or Demande.objects.select_related("candidat", "campagne").all()
    return [
        {
            "ID": d.id_dde,
            "Date demande": d.dat_dde,
            "État": d.get_etat_dde_display(),
            "Réponse": d.reponse or "",
            "Campagne": d.campagne.cod_anne,
            "Candidat": f"{d.candidat.nom_cand} {d.candidat.pren_cand}",
            "Email candidat": d.candidat.email,
            "Année obtention diplôme": d.anne_obt_dip,
            "CV": _file_label(d.cv),
            "Fichier diplôme": _file_label(d.diplome_fichier),
        }
        for d in qs.order_by("-dat_dde", "-id_dde")
    ]


def _rows_for_newsletters():
    return [
        {"Email": n.email, "Date inscription": n.date_inscription}
        for n in Newsletter.objects.all().order_by("-date_inscription")
    ]


def _rows_for_contact_messages():
    return [
        {
            "ID": m.id,
            "Nom": m.nom,
            "Prénom": m.prenom or "",
            "Email": m.email,
            "Message": m.message,
            "Date envoi": m.date_envoi,
        }
        for m in ContactMessage.objects.all().order_by("-date_envoi")
    ]


def _build_rows(model_key, queryset=None):
    builders = {
        "domaines": _rows_for_domaines,
        "diplomes": _rows_for_diplomes,
        "campagnes": _rows_for_campagnes,
        "candidats": _rows_for_candidats,
        "demandes": lambda: _rows_for_demandes(queryset),
        "newsletters": _rows_for_newsletters,
        "contact-message": _rows_for_contact_messages,
    }
    return builders[model_key]()


def export_model_to_excel(model_key: str, queryset=None):
    """
    Exporte les données d'un modèle autorisé vers un fichier Excel (.xlsx).
    Retourne (HttpResponse, None) en cas de succès, (None, message_erreur) sinon.
    """
    model_key = model_key.lower().strip()

    if model_key not in EXPORTABLE_MODELS:
        allowed = ", ".join(sorted(EXPORTABLE_MODELS))
        return None, f"Modèle '{model_key}' non exportable. Valeurs autorisées : {allowed}."

    rows = _build_rows(model_key, queryset=queryset)
    if not rows:
        return None, f"Aucune donnée à exporter pour '{model_key}'."

    df = pd.DataFrame(rows)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recrutplus_{model_key}_{timestamp}.xlsx"

    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'

    sheet_name = model_key.replace("-", "_")[:31]
    with pd.ExcelWriter(response, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)

    return response, None
