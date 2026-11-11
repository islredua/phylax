from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("llm", "0006_vulnerability_description")]

    operations = [
        migrations.AlterField(
            model_name="inferencelog",
            name="task",
            field=models.CharField(
                choices=[
                    ("ASSET_CRITICALITY", "Criticidad de activo"),
                    ("CTI_EXTRACTION", "Extracción CTI"),
                    ("EXEC_NARRATIVE", "Narrativa ejecutiva"),
                    ("DETECTION_PLANNER", "Planificador de detección"),
                    ("ORG_PROFILE_DRAFT", "Borrador del perfil de la organización"),
                    ("VULN_ASSESSMENT", "Consolidación de vulnerabilidades"),
                    ("RISK_ASSESSMENT", "Valoración de riesgos"),
                    ("VULN_DESCRIBE", "Redacción de vulnerabilidad"),
                    ("RISK_NARRATIVE", "Redacción del riesgo para la dirección"),
                ],
                max_length=32,
            ),
        ),
    ]
