from django.test import TestCase
from rest_framework.views import APIView

# Create your tests here.
class TestEmailView(APIView):
    def post(self, request):
        try:
            result = send_mail(
                'Test Email',
                'Ceci est un test',
                'shinnyoyere@gmail.com',
                [request.data.get('email')],
                fail_silently=False,
            )
            return Response({"success": f"Email envoyé: {result}"})
        except Exception as e:
            return Response({"error": str(e)}, status=500)