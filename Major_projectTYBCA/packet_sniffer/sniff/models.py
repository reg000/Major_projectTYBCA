from django.db import models

class Packet(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    src_mac = models.CharField(max_length=17)
    dest_mac = models.CharField(max_length=17)
    src_port = models.IntegerField(null=True, blank=True)
    dest_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10)
    summary = models.TextField()

    def __str__(self):
        return f"{self.src_ip} -> {self.dest_ip} ({self.protocol})"

class Session(models.Model):
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    pcap_file = models.FileField(upload_to="pcap_files/", null=True, blank=True)

    def __str__(self):
        return f"Session {self.pk} - {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}"
