# Generated by Django 5.1.7 on 2025-03-26 04:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App', '0007_visionmission'),
    ]

    operations = [
        migrations.AlterField(
            model_name='aboutus',
            name='core_values',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='core_values_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='cta_text',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='history_description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='history_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='impact_description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='impact_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='introduction_description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='introduction_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='milestones',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='mission_description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='mission_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='programs',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='programs_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='team_title',
            field=models.CharField(blank=True, max_length=200),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='vision_description',
            field=models.TextField(blank=True),
        ),
        migrations.AlterField(
            model_name='aboutus',
            name='vision_title',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
