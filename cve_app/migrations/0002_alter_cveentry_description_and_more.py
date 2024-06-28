# Generated by Django 4.2.10 on 2024-06-24 02:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cve_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cveentry',
            name='description',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='cveentry',
            name='modified_date',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='cveentry',
            name='published_date',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='cveentry',
            name='references',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='cveentry',
            name='vector_string',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='cveentry',
            name='version',
            field=models.CharField(blank=True, max_length=10, null=True),
        ),
    ]
