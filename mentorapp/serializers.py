from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import (
    User, MenteeProfile, MentorProfile, Skill, MentorAvailability,
    MentorshipRequest, MentorshipRelationship, Session, Feedback, Payment, Notification
)
from django.core.files.base import ContentFile
import base64
import json
from decimal import Decimal
from django.utils import timezone

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'user_type', 'password', 'date_joined', 'profile_completed']
        extra_kwargs = {
            'password': {'write_only': True},
            'date_joined': {'read_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class SkillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skill
        fields = ['id', 'skill_name', 'description']

class MentorAvailabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = MentorAvailability
        fields = ['id', 'day_of_week', 'start_time', 'end_time', 'is_recurring']

class MentorProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    skills = SkillSerializer(many=True, read_only=True)
    availability = MentorAvailabilitySerializer(many=True, read_only=True)
    name = serializers.SerializerMethodField()
    
    class Meta:
        model = MentorProfile
        fields = ['id', 'user', 'name', 'profile_image', 'bio', 'designation', 
                 'company', 'experience_years', 'skills', 'hourly_rate', 
                 'availability', 'location', 'linkedin_url', 'github_url', 'website']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

class MenteeProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    skills = SkillSerializer(many=True, read_only=True)
    name = serializers.SerializerMethodField()
    
    class Meta:
        model = MenteeProfile
        fields = ['id', 'user', 'name', 'profile_image', 'bio', 
                 'designation', 'experience_level', 'skills',
                 'location', 'linkedin_url', 'github_url']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

class MentorListSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    skills = SkillSerializer(many=True, read_only=True)
    availability = MentorAvailabilitySerializer(many=True, read_only=True)
    name = serializers.SerializerMethodField()

    class Meta:
        model = MentorProfile
        fields = ['id', 'user', 'name', 'profile_image', 'designation', 
                 'company', 'experience_years', 'skills', 'hourly_rate', 
                 'availability', 'location', 'bio', 'linkedin_url', 
                 'github_url', 'website']

    def get_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

class MentorshipRequestSerializer(serializers.ModelSerializer):
    mentee = serializers.SerializerMethodField()
    mentor = serializers.SerializerMethodField()
    mentor_id = serializers.IntegerField(write_only=True)
    mentee_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = MentorshipRequest
        fields = ['id', 'mentor', 'mentee', 'message', 'status', 'created_at', 'mentor_id', 'mentee_id']
        read_only_fields = ['id', 'created_at']

    def get_mentee(self, obj):
        return {
            'id': obj.mentee.id,
            'user': {
                'id': obj.mentee.user.id,
                'first_name': obj.mentee.user.first_name,
                'last_name': obj.mentee.user.last_name,
                'email': obj.mentee.user.email
            },
            'profile_image': obj.mentee.profile_image.url if obj.mentee.profile_image else None
        }

    def get_mentor(self, obj):
        return {
            'id': obj.mentor.id,
            'user': {
                'id': obj.mentor.user.id,
                'first_name': obj.mentor.user.first_name,
                'last_name': obj.mentor.user.last_name,
                'email': obj.mentor.user.email
            },
            'designation': obj.mentor.designation,
            'profile_image': obj.mentor.profile_image.url if obj.mentor.profile_image else None
        }

    def create(self, validated_data):
        mentor_id = validated_data.pop('mentor_id')
        mentee_id = validated_data.pop('mentee_id')
        
        mentor = MentorProfile.objects.get(id=mentor_id)
        mentee = MenteeProfile.objects.get(id=mentee_id)
        
        return MentorshipRequest.objects.create(
            mentor=mentor,
            mentee=mentee,
            **validated_data
        )

class MentorshipRelationshipSerializer(serializers.ModelSerializer):
    mentee = MenteeProfileSerializer(read_only=True)
    mentor = MentorProfileSerializer(read_only=True)
    request = MentorshipRequestSerializer(read_only=True)
    mentee_id = serializers.IntegerField(write_only=True)
    mentor_id = serializers.IntegerField(write_only=True)
    request_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = MentorshipRelationship
        fields = ['id', 'mentee', 'mentor', 'request', 'mentee_id', 
                 'mentor_id', 'request_id', 'status', 'start_date', 
                 'end_date', 'goals']

    def create(self, validated_data):
        mentee_id = validated_data.pop('mentee_id')
        mentor_id = validated_data.pop('mentor_id')
        request_id = validated_data.pop('request_id')
        mentee = MenteeProfile.objects.get(id=mentee_id)
        mentor = MentorProfile.objects.get(id=mentor_id)
        request = MentorshipRequest.objects.get(id=request_id)
        return MentorshipRelationship.objects.create(
            mentee=mentee, mentor=mentor, request=request, **validated_data
        )

class SessionSerializer(serializers.ModelSerializer):
    relationship = serializers.SerializerMethodField()

    class Meta:
        model = Session
        fields = ['id', 'relationship', 'session_date', 'start_time', 'end_time', 'status']
        read_only_fields = ['id', 'relationship']

    def get_relationship(self, obj):
        if obj.relationship:
            return {
                'id': obj.relationship.id,
                'mentee': {
                    'id': obj.relationship.mentee.id,
                    'user': {
                        'id': obj.relationship.mentee.user.id,
                        'username': obj.relationship.mentee.user.username,
                        'first_name': obj.relationship.mentee.user.first_name,
                        'last_name': obj.relationship.mentee.user.last_name
                    }
                },
                'mentor': {
                    'id': obj.relationship.mentor.id,
                    'user': {
                        'id': obj.relationship.mentor.user.id,
                        'username': obj.relationship.mentor.user.username,
                        'first_name': obj.relationship.mentor.user.first_name,
                        'last_name': obj.relationship.mentor.user.last_name
                    }
                }
            }
        return None

class FeedbackSerializer(serializers.ModelSerializer):
    session = SessionSerializer(read_only=True)
    session_id = serializers.IntegerField(write_only=True)

    class Meta:
        model = Feedback
        fields = ['id', 'session', 'session_id', 'rating', 'comment']

    def create(self, validated_data):
        session_id = validated_data.pop('session_id')
        session = Session.objects.get(id=session_id)
        return Feedback.objects.create(session=session, **validated_data)

class PaymentSerializer(serializers.ModelSerializer):
    mentee = MenteeProfileSerializer(read_only=True)
    mentor = MentorProfileSerializer(read_only=True)
    session = SessionSerializer(read_only=True)
    mentee_id = serializers.IntegerField(write_only=True)
    mentor_id = serializers.IntegerField(write_only=True)
    session_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = Payment
        fields = ['id', 'mentee', 'mentor', 'amount', 'status', 'session', 'mentee_id', 'mentor_id', 'session_id']
        read_only_fields = ['transaction_id', 'created_at', 'updated_at']
        extra_kwargs = {
            'amount': {'required': True},
            'status': {'required': True}
        }

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError('Amount must be greater than zero')
        return value

    def validate_status(self, value):
        valid_statuses = ['Pending', 'Completed', 'Failed']
        if value not in valid_statuses:
            raise serializers.ValidationError(f'Invalid status. Must be one of: {valid_statuses}')
        return value

    def create(self, validated_data):
        mentee_id = validated_data.pop('mentee_id')
        mentor_id = validated_data.pop('mentor_id')
        session_id = validated_data.pop('session_id', None)
        
        mentee = MenteeProfile.objects.get(id=mentee_id)
        mentor = MentorProfile.objects.get(id=mentor_id)
        
        payment = Payment.objects.create(
            mentee=mentee,
            mentor=mentor,
            **validated_data,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        
        if session_id:
            session = Session.objects.get(id=session_id)
            session.payment = payment
            session.save()
        
        return payment

class NotificationSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(write_only=True)
    username = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ['id', 'user_id', 'username', 'type', 'content', 'related_id', 'is_read', 'created_at']
        read_only_fields = ['created_at']

    def get_username(self, obj):
        return obj.user.username if obj.user else None

    def create(self, validated_data):
        user_id = validated_data.pop('user_id')
        try:
            user = User.objects.get(id=user_id)
            notification = Notification.objects.create(user=user, **validated_data)
            return notification
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")
