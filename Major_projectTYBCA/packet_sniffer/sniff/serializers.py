from rest_framework import serializers
from .models import Packet

class packetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Packet
        fields = "__all__"