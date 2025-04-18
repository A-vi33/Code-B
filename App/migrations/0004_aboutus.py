# Generated by Django 5.1.7 on 2025-03-25 10:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('App', '0003_banner_initiative_statistic_visionmission_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='AboutUs',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('introduction_title', models.CharField(default='Welcome to [NGO Name]', max_length=150)),
                ('introduction_description', models.TextField(default='We are a passionate team dedicated to making a difference in the lives of underprivileged communities through education, healthcare, and empowerment.')),
                ('history_title', models.CharField(default='Our Story', max_length=150)),
                ('history_description', models.TextField(default='Founded in 2015, [NGO Name] started as a small community initiative. Today, we have empowered over 10,000 individuals across 50+ villages.')),
                ('core_values_title', models.CharField(default='Our Core Values', max_length=150)),
                ('core_values', models.TextField(default='Integrity\nEmpathy\nInclusivity\nTransparency')),
                ('programs_title', models.CharField(default='Our Programs', max_length=150)),
                ('programs', models.TextField(default='Providing free educational resources for children.\nRunning health camps for rural areas.\nOffering vocational training for women.')),
                ('team_title', models.CharField(default='Meet Our Team', max_length=150)),
                ('team_description', models.TextField(default='John Doe, Founder\nWith a vision for a better world, John has been leading the organization since its inception.\n\nJane Smith, Program Manager\nJane oversees all our programs and ensures they are impactful and sustainable.')),
                ('impact_title', models.CharField(default='Our Impact', max_length=150)),
                ('impact_description', models.TextField(default='In the past year, we have achieved:\nEducated over 5,000 children.\nConducted 50+ health camps.\nEmpowered 200 women with vocational training.')),
                ('cta_text', models.CharField(default='Become a part of the change. Volunteer today or donate to help transform lives.', max_length=200)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
