import pandas as pd
from django.http import HttpResponse
from django.apps import apps

def export_model_to_excel(model_name: str):
    """
    Exporte les données de n'importe quel modèle Django vers Excel (.xlsx)
    """
    try:
        # Récupération du modèle dynamiquement
        model = apps.get_model('recrutement', model_name.capitalize())
    except LookupError:
        return None, f"Modèle '{model_name}' introuvable."

    # Récupération des données
    queryset = model.objects.all()
    if not queryset.exists():
        return None, f"Aucune donnée trouvée pour le modèle '{model_name}'."

    # Conversion en DataFrame Pandas
    df = pd.DataFrame(list(queryset.values()))

    # Création du fichier Excel en mémoire
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename="{model_name}.xlsx"'

    # Écriture dans le fichier Excel
    with pd.ExcelWriter(response, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name=model_name.capitalize())

    return response, None




from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from ..utils.export_excel import export_model_to_excel

@api_view(['GET'])
@permission_classes([IsAdminUser])
def export_any_model(request, model_name):
    """
    Exporte le contenu d’un modèle en Excel via /api/export/<model_name>/
    """
    response, error = export_model_to_excel(model_name.lower())
    if error:
        return Response({"error": error}, status=404)
    return response

