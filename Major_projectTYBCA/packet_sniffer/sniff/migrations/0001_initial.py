# Generated by Django 5.1.5 on 2025-02-18 17:56

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Packet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('src_ip', models.GenericIPAddressField()),
                ('dest_ip', models.GenericIPAddressField()),
                ('src_mac', models.CharField(max_length=17)),
                ('dest_mac', models.CharField(max_length=17)),
                ('src_port', models.IntegerField(blank=True, null=True)),
                ('dest_port', models.IntegerField(blank=True, null=True)),
                ('protocol', models.CharField(max_length=10)),
                ('summary', models.TextField()),
            ],
        ),
    ]
