# Generated by Django 5.1.7 on 2025-03-26 13:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App', '0008_alter_aboutus_core_values_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='initiative',
            name='created_at',
        ),
        migrations.RemoveField(
            model_name='initiative',
            name='updated_at',
        ),
        migrations.RemoveField(
            model_name='statistic',
            name='created_at',
        ),
        migrations.RemoveField(
            model_name='statistic',
            name='updated_at',
        ),
        migrations.RemoveField(
            model_name='visionmission',
            name='created_at',
        ),
        migrations.AlterField(
            model_name='banner',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='banner',
            name='image_url',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='banner',
            name='title',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='initiative',
            name='description',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='initiative',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='initiative',
            name='image_url',
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='initiative',
            name='status',
            field=models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active', max_length=20),
        ),
        migrations.AlterField(
            model_name='initiative',
            name='title',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='statistic',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='statistic',
            name='status',
            field=models.CharField(choices=[('active', 'Active'), ('inactive', 'Inactive')], default='active', max_length=20),
        ),
        migrations.AlterField(
            model_name='statistic',
            name='value',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='visionmission',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AlterField(
            model_name='visionmission',
            name='mission_description',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='visionmission',
            name='mission_title',
            field=models.CharField(max_length=200),
        ),
        migrations.AlterField(
            model_name='visionmission',
            name='vision_description',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='visionmission',
            name='vision_title',
            field=models.CharField(max_length=200),
        ),
    ]
