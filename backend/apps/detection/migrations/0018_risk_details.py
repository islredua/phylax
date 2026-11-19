from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("detection", "0017_risk_review_at_risk_target_date")]

    operations = [
        migrations.AddField(
            model_name="risk",
            name="details",
            field=models.TextField(
                blank=True,
                help_text="Detalle técnico: software y versiones, cadena de ataque, qué lo sustenta.",
            ),
        ),
    ]
