# Generated by Django 3.1.5 on 2021-02-22 18:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app01', '0004_auto_20210222_2043'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rentdetails',
            name='bikeid',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='app01.bike'),
        ),
    ]
