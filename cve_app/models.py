from django.db import models

class CVEEntry(models.Model):
    cve_id = models.CharField(max_length=20)
    description = models.CharField(max_length=100, null=True, blank=True)
    published_date = models.CharField(max_length=50, null=True, blank=True)
    modified_date = models.CharField(max_length=50, null=True, blank=True)
    affected_platform = models.CharField(max_length=200, null=True, blank=True)
    version = models.CharField(max_length=10, null=True, blank=True)
    vector_string = models.CharField(max_length=100, null=True, blank=True)
    base_score = models.CharField(max_length=20, null=True, blank=True)
    base_severity = models.CharField(max_length=20, null=True, blank=True)
    references = models.CharField(max_length=100, null=True, blank=True)
    cwe = models.CharField(max_length=20, null=True, blank=True)
    assigner = models.CharField(max_length=20, null=True, blank=True)

    def __str__(self):
        return self.cve_id
