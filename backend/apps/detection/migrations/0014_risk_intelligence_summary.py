from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("detection", "0013_risk_description")]

    operations = [
        migrations.AddField(
            model_name="risk",
            name="intelligence_summary",
            field=models.TextField(
                blank=True,
                help_text="Qué dice la inteligencia de amenazas (KEV, EPSS, fuentes) y cómo pesa.",
            ),
        ),
    ]
