from django.db import models

class CVEEntry(models.Model):
    entry_id = models.CharField(max_length=100, primary_key=True)
    cve_id = models.CharField(max_length=20)
    description = models.CharField(max_length=100, null=True, blank=True)
    published_date = models.DateTimeField(blank=True, null=True)
    last_modified_date = models.DateTimeField(blank=True, null=True)
    affected_platform = models.CharField(max_length=200, null=True, blank=True)
    cvss_version = models.CharField(max_length=10, null=True, blank=True)
    base_score = models.CharField(max_length=20, null=True, blank=True)
    base_severity = models.CharField(max_length=20, null=True, blank=True)
    references = models.CharField(max_length=100, null=True, blank=True)
    cwe = models.CharField(max_length=20, null=True, blank=True)
    assigner = models.CharField(max_length=20, null=True, blank=True)

    class Meta:
        db_table = 'entire_cve_list'

    def __str__(self):
        return self.cve_id


class RansomwareCVEEntry(models.Model):
    cve_id = models.CharField(max_length=100, primary_key=True)
    description = models.TextField(blank=True)
    mitigation = models.TextField(blank=True)
    ransomware = models.CharField(max_length=500, blank=True)
    cve_references_url = models.TextField(blank=True)
    rw_references_url = models.TextField(blank=True)

    class Meta:
        db_table = 'ransomware_cve_list'