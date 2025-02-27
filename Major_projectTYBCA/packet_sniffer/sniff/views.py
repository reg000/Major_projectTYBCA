from django.shortcuts import render, redirect
from django.http import JsonResponse
from .models import Packet
from .sniffer import start_sniffing, stop_sniffing
import threading

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import packetSerializer

#Rest API

@api_view(['GET'])
def get_packets_api(request):
    packets = Packet.objects.all().order_by('-timestamp')[:50]  
    serializer = packetSerializer(packets, many=True)  
    return Response(serializer.data)  


#Views

def dashboard(request):
    packets = Packet.objects.all().order_by("-timestamp")[:50]  
    return render(request, "dashboard.html", {"packets": packets})

def start_capture(request):
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()
    return JsonResponse({"status": "Sniffing started"})

def stop_capture(request):
    stop_sniffing()
    return JsonResponse({"status": "Sniffing stopped"})

