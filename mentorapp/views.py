from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    UserSerializer, 
    MentorProfileSerializer, 
    MenteeProfileSerializer, 
    SkillSerializer, 
    MentorListSerializer,
    MentorshipRequestSerializer,
    MentorshipRelationshipSerializer,
    NotificationSerializer,
    PaymentSerializer,
    SessionSerializer,
    FeedbackSerializer
)
from .models import MenteeProfile, MentorProfile, Skill, MentorAvailability, MentorshipRequest, MentorshipRelationship, Notification, Payment, Session, Feedback
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
import json
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
import time
from decimal import Decimal
import os
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from django.utils import timezone
from datetime import datetime, timedelta
from django.db.models import Q, Sum, Avg
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

User = get_user_model()

from django.conf import settings
import razorpay
import json
import random

# Initialize Razorpay client
razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
)


@api_view(['POST'])
@permission_classes([AllowAny])  # 🔹 Allow access to everyone (unauthenticated users)
def signup(request):
    try:
        # Validate required fields
        required_fields = ['email', 'username', 'password', 'user_type']
        for field in required_fields:
            if field not in request.data:
                return Response(
                    {"message": f"{field} is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Check if email exists
        if User.objects.filter(email=request.data['email']).exists():
            return Response(
                {"message": "An account with this email already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if username exists
        if User.objects.filter(username=request.data['username']).exists():
            return Response(
                {"message": "This username is already taken"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = UserSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            response_data = {
                "message": "Signup successful.",
                "redirect_url": "/profileSetup" if user.user_type == "mentee" else "/mentorProfileSetup",
                "token": access_token,
                "user": {
                    "email": user.email,
                    "user_type": user.user_type
                }
            }

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        # Format validation errors into a single message
        error_message = next(iter(serializer.errors.values()))[0]
        return Response(
            {"message": error_message},
            status=status.HTTP_400_BAD_REQUEST
        )
        
    except Exception as e:
        return Response(
            {"message": "Registration failed. Please try again."}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    try:
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {"message": "Both email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"message": "No account found with this email"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check password
        if not user.check_password(password):
            return Response(
                {"message": "Invalid password"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Generate token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # For admin users, always redirect to admin dashboard
        if user.is_staff or user.is_superuser or user.user_type.lower() == 'admin':
            redirect_url = '/dashboard/admin'
            profile_completed = True  # Admin doesn't need profile completion
        else:
            # For non-admin users, check profile completion
            if not getattr(user, 'profile_completed', False):
                redirect_url = '/profileSetup' if user.user_type == 'mentee' else '/mentorProfileSetup'
            else:
                redirect_url = {
                    'mentor': '/dashboard/mentor',
                    'mentee': '/dashboard/mentee'
                }.get(user.user_type.lower(), '/dashboard')
            profile_completed = getattr(user, 'profile_completed', False)

        response_data = {
            "message": "Login successful",
            "token": access_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "user_type": user.user_type,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_staff": user.is_staff,
                "is_superuser": user.is_superuser,
                "profile_completed": profile_completed
            },
            "redirect_url": redirect_url
        }

        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            {"message": "Login failed. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def google_auth(request):
    try:
        token = request.data.get('token')
        
        # Add clock skew tolerance
        idinfo = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            settings.GOOGLE_OAUTH2_CLIENT_ID,
            clock_skew_in_seconds=10  # Add tolerance for clock skew
        )

        # Verify issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Invalid issuer')

        # Get user info from token
        email = idinfo['email']
        first_name = idinfo.get('given_name', '')
        last_name = idinfo.get('family_name', '')
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
            is_new_user = False
        except User.DoesNotExist:
            is_new_user = True
            return Response({
                "isNewUser": True,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "googleToken": token
            })

        # Existing user - generate token and return user data
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            "isNewUser": False,
            "token": access_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "user_type": user.user_type,
                "profile_completed": user.profile_completed
            },
            "redirect_url": f"/dashboard/{user.user_type.lower()}"
        })

    except ValueError as e:
        return Response(
            {"message": f"Invalid token: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {"message": "Google authentication failed"},
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def complete_google_signup(request):
    try:
        google_token = request.data.get('token')
        user_type = request.data.get('user_type')

        # Verify the Google token with clock skew tolerance
        idinfo = id_token.verify_oauth2_token(
            google_token,
            requests.Request(),
            settings.GOOGLE_OAUTH2_CLIENT_ID,
            clock_skew_in_seconds=10
        )

        # Verify issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Invalid issuer')

        email = idinfo['email']
        first_name = idinfo.get('given_name', '')
        last_name = idinfo.get('family_name', '')

        # Create new user
        user = User.objects.create_user(
            username=f"{email.split('@')[0]}_{int(time.time())}",  # Ensure unique username
            email=email,
            first_name=first_name,
            last_name=last_name,
            user_type=user_type,
            password=None  # No password for Google users
        )

        # Generate token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        return Response({
            "token": access_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "user_type": user_type,
                "profile_completed": False
            },
            "redirect_url": f"/{'profileSetup' if user_type == 'mentee' else 'mentorProfileSetup'}"
        })

    except ValueError as e:
        return Response(
            {"message": f"Invalid token: {str(e)}"},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {"message": "Failed to complete signup"},
            status=status.HTTP_400_BAD_REQUEST
        )

class MentorProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        try:
            mentor_profile, created = MentorProfile.objects.get_or_create(user=request.user)
            
            # Handle profile image
            if 'profile_image' in request.FILES:
                mentor_profile.profile_image = request.FILES['profile_image']
            
            # Update basic fields
            basic_fields = ['bio', 'designation', 'company', 'experience_years', 'location', 
                          'linkedin_url', 'github_url', 'website']
            for field in basic_fields:
                if field in request.data:
                    value = request.data.get(field, [''])[0] if isinstance(request.data.get(field), list) else request.data.get(field, '')
                    setattr(mentor_profile, field, value)
            
            # Handle hourly rate
            hourly_rate = request.data.get('hourly_rate')
            if isinstance(hourly_rate, list):
                hourly_rate = hourly_rate[0]
            try:
                if hourly_rate:
                    mentor_profile.hourly_rate = float(hourly_rate)
            except (ValueError, TypeError):
                pass
            
            # Save the profile first
            mentor_profile.save()
            
            # Handle skills
            if 'skills' in request.data:
                try:
                    skills_data = json.loads(request.data['skills'])
                    if isinstance(skills_data, list):
                        mentor_profile.skills.clear()
                        skill_objects = Skill.objects.filter(id__in=skills_data)
                        mentor_profile.skills.add(*skill_objects)
                except json.JSONDecodeError:
                    pass
            
            # Handle availability
            if 'availability' in request.data:
                try:
                    availability_data = json.loads(request.data['availability'])
                    # Create availability entries
                    for day, times in availability_data.items():
                        if times.get('available'):
                            MentorAvailability.objects.create(
                                mentor=mentor_profile,
                                day_of_week=day,
                                start_time=times.get('start_time', '09:00'),
                                end_time=times.get('end_time', '17:00'),
                                is_recurring=True
                            )
                except json.JSONDecodeError:
                    pass
            
            # Update user's profile completion status
            request.user.profile_completed = True
            request.user.save()
            
            return Response({
                "message": "Profile completed successfully",
                "redirect_url": "/mentorProfileSetup"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"message": "Failed to update profile. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request):
        try:
            mentor_profile = request.user.mentorprofile
            
            # Handle profile image
            if 'profile_image' in request.FILES:
                mentor_profile.profile_image = request.FILES['profile_image']
            
            # Update basic fields
            basic_fields = ['bio', 'designation', 'company', 'experience_years', 'location', 
                          'linkedin_url', 'github_url', 'website']
            for field in basic_fields:
                if field in request.data:
                    setattr(mentor_profile, field, request.data.get(field))
            
            # Handle hourly rate
            if 'hourly_rate' in request.data:
                try:
                    hourly_rate = request.data.get('hourly_rate')
                    if isinstance(hourly_rate, str):
                        hourly_rate = float(hourly_rate)
                    mentor_profile.hourly_rate = hourly_rate
                except (ValueError, TypeError):
                    pass
            
            # Save the profile first
            mentor_profile.save()
            
            # Handle skills
            if 'skills' in request.data:
                try:
                    skills_data = json.loads(request.data['skills'])
                    if isinstance(skills_data, list):
                        mentor_profile.skills.clear()
                        skill_objects = Skill.objects.filter(id__in=skills_data)
                        mentor_profile.skills.add(*skill_objects)
                except json.JSONDecodeError:
                    pass
            
            # Handle availability
            if 'availability' in request.data:
                try:
                    availability_data = json.loads(request.data['availability'])
                    # Clear existing availability
                    mentor_profile.availability.all().delete()
                    
                    # Create new availability entries
                    for day, times in availability_data.items():
                        if times.get('available'):
                            MentorAvailability.objects.create(
                                mentor=mentor_profile,
                                day_of_week=day,
                                start_time=times.get('start_time', '09:00'),
                                end_time=times.get('end_time', '17:00'),
                                is_recurring=True
                            )
                except json.JSONDecodeError:
                    pass
            
            return Response({
                "message": "Profile updated successfully",
                "profile_id": mentor_profile.id
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                "message": "Failed to update profile",
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class MenteeProfileView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        try:
            # Get or create mentee profile
            mentee_profile, created = MenteeProfile.objects.get_or_create(user=request.user)
            
            # Handle profile image
            if 'profile_image' in request.FILES:
                mentee_profile.profile_image = request.FILES['profile_image']
            
            # Update basic fields
            mentee_profile.bio = request.data.get('bio', '')
            mentee_profile.designation = request.data.get('designation', '')
            mentee_profile.experience_level = request.data.get('experience_level', '')
            mentee_profile.location = request.data.get('location', '')
            mentee_profile.linkedin_url = request.data.get('linkedin_url', '')
            mentee_profile.github_url = request.data.get('github_url', '')
            
            # Save the profile first
            mentee_profile.save()
            
            # Handle skills - expecting a list of skill IDs
            skills_data = json.loads(request.data.get('skills', '[]'))
            if skills_data:
                # Clear existing skills and add new ones
                mentee_profile.skills.clear()
                skill_objects = Skill.objects.filter(id__in=skills_data)
                mentee_profile.skills.add(*skill_objects)
            
            # Update user's profile completion status
            request.user.profile_completed = True
            request.user.save()
            
            return Response({
                "message": "Profile updated successfully",
                "profile_id": mentee_profile.id,
                "redirect_url": "/login"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                "message": "Failed to update profile",
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_mentee_profile(request):
    """
    Create a new mentee profile for the authenticated user.
    """
    if request.user.user_type != 'mentee':
        return Response(
            {'message': 'Only mentees can create mentee profiles'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        # First, create the mentee profile
        serializer = MenteeProfileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        mentee_profile = serializer.save(user=request.user)

        # Add skills to mentee_profile_skills table
        skills = request.data.getlist('skills')
        if skills:
            mentee_profile.skills.set(skills)

        # Create notification for admins
        admin_users = User.objects.filter(user_type='admin')
        for admin in admin_users:
            Notification.objects.create(
                user=admin,
                type='system',
                content=f'New mentee {request.user.first_name} {request.user.last_name} has registered. Please review their profile.',
                related_id=mentee_profile.id
            )

        # Set profile_completed to True
        request.user.profile_completed = True
        request.user.save()

        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def skill_list(request):
    """
    List all skills or create a new skill.
    Regular users can only create skills, which will notify admins.
    Admins can create skills directly.
    """
    if request.method == 'GET':
        skills = Skill.objects.all().order_by('skill_name')
        serializer = SkillSerializer(skills, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        if not request.user.is_authenticated:
            return Response(
                {'message': 'Authentication required to create skills'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        serializer = SkillSerializer(data=request.data)
        if serializer.is_valid():
            skill = serializer.save()
            
            # If a non-admin user creates a skill, notify admins
            if not request.user.is_staff:
                # Get all admin users
                admin_users = User.objects.filter(is_staff=True)
                user_name = f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username
                
                for admin in admin_users:
                    Notification.objects.create(
                        user=admin,
                        type='skill',
                        content=f"New skill '{skill.skill_name}' added by mentor {user_name}",
                        related_id=skill.id
                    )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(
            {"message": "Invalid skill data", "errors": serializer.errors}, 
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def skill_detail(request, pk):
    """
    Retrieve, update or delete a skill.
    Regular users can only retrieve skills.
    Only admins can update or delete skills.
    """
    try:
        skill = Skill.objects.get(pk=pk)
    except Skill.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = SkillSerializer(skill)
        return Response(serializer.data)

    # Only admin can edit or delete skills
    if not request.user.is_staff:
        return Response(
            {"message": "Admin access required"}, 
            status=status.HTTP_403_FORBIDDEN
        )

    if request.method == 'PUT':
        serializer = SkillSerializer(skill, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        skill.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_mentor_profile(request):
    try:
        # Get or create mentor profile
        mentor_profile, created = MentorProfile.objects.get_or_create(user=request.user)
        
        # Handle profile image
        if 'profile_image' in request.FILES:
            mentor_profile.profile_image = request.FILES['profile_image']
        
        # Update basic fields
        mentor_profile.bio = request.data.get('bio', '')
        mentor_profile.designation = request.data.get('designation', '')
        mentor_profile.company = request.data.get('company', '')
        mentor_profile.experience_years = request.data.get('experience_years', '')
        mentor_profile.hourly_rate = float(request.data.get('hourly_rate', 0))
        mentor_profile.location = request.data.get('location', '')
        mentor_profile.linkedin_url = request.data.get('linkedin_url', '')
        mentor_profile.github_url = request.data.get('github_url', '')
        mentor_profile.website = request.data.get('website', '')
        
        # Save the profile first
        mentor_profile.save()
        
        # Handle skills
        if 'skills' in request.data:
            try:
                skills_data = json.loads(request.data['skills'])
                if isinstance(skills_data, list):
                    mentor_profile.skills.clear()
                    skill_objects = Skill.objects.filter(id__in=skills_data)
                    mentor_profile.skills.add(*skill_objects)
            except json.JSONDecodeError:
                pass
        
        # Handle availability
        if 'availability' in request.data:
            try:
                availability_data = json.loads(request.data['availability'])
                # Clear existing availability
                mentor_profile.availability.all().delete()
                
                # Create new availability entries
                for day, times in availability_data.items():
                    if times.get('available'):
                        MentorAvailability.objects.create(
                            mentor=mentor_profile,
                            day_of_week=day,
                            start_time=times.get('start_time', '09:00'),
                            end_time=times.get('end_time', '17:00'),
                            is_recurring=True
                        )
            except json.JSONDecodeError:
                pass
        
        return Response({
            "message": "Profile updated successfully",
            "profile_id": mentor_profile.id
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            "message": "Failed to update profile",
            "error": str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_all_mentors(request):
    try:
        mentors = MentorProfile.objects.select_related('user').prefetch_related('skills', 'availability').all()
        
        # Prepare response with feedback data
        mentor_data = []
        for mentor in mentors:
            # Get all sessions for this mentor
            mentor_sessions = Session.objects.filter(relationship__mentor=mentor)
            
            # Get all feedbacks for these sessions
            feedbacks = Feedback.objects.filter(session__in=mentor_sessions)
            
            # Calculate feedback count and average rating
            feedback_count = feedbacks.count()
            average_rating = feedbacks.aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0
            
            # Get serialized data
            serialized_mentor = MentorListSerializer(mentor).data
            
            # Add feedback data
            serialized_mentor['feedback_count'] = feedback_count
            serialized_mentor['average_rating'] = average_rating
            
            mentor_data.append(serialized_mentor)
        
        return Response(mentor_data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response(
            {"message": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([AllowAny])
def get_mentor_by_id(request, mentor_id):
    try:
        # Use select_related for user and prefetch_related for skills and availability
        mentor = MentorProfile.objects.select_related('user').prefetch_related('skills', 'availability').get(id=mentor_id)
        
        # Get all skills for this mentor
        mentor_skills = mentor.skills.all()
        
        # Fix the availability f-string
        availability_data = [{
            'day': avail.day_of_week,
            'start_time': avail.start_time,
            'end_time': avail.end_time
        } for avail in mentor.availability.all()]
        
        serializer = MentorListSerializer(mentor)
        data = serializer.data
        
        # Ensure hourly rate is properly formatted as a string
        if 'hourly_rate' in data and data['hourly_rate'] is not None:
            data['hourly_rate'] = str(data['hourly_rate'])
        
        # Get feedback data
        mentor_sessions = Session.objects.filter(relationship__mentor=mentor)
        feedbacks = Feedback.objects.filter(session__in=mentor_sessions)
        
        # Calculate feedback count and average rating
        feedback_count = feedbacks.count()
        average_rating = feedbacks.aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0
        
        # Add feedback data to response
        data['feedback_count'] = feedback_count
        data['average_rating'] = average_rating
        
        return Response(data, status=status.HTTP_200_OK)
    except MentorProfile.DoesNotExist:
        return Response(
            {"message": "Mentor not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"message": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_matching_mentors(request):
    try:
        # Get the logged-in user's mentee profile
        mentee = MenteeProfile.objects.get(user=request.user)
        
        # Get the mentee's skills
        mentee_skills = set(mentee.skills.all())
        
        # Get all mentors and filter them based on matching skills
        all_mentors = MentorProfile.objects.all()
        matching_mentors = []
        
        for mentor in all_mentors:
            mentor_skills = set(mentor.skills.all())
            # Check if there's any overlap between mentor and mentee skills
            if mentor_skills.intersection(mentee_skills):
                matching_mentors.append(mentor)
        
        # Prepare response with feedback data
        mentor_data = []
        for mentor in matching_mentors:
            # Get all sessions for this mentor
            mentor_sessions = Session.objects.filter(relationship__mentor=mentor)
            
            # Get all feedbacks for these sessions
            feedbacks = Feedback.objects.filter(session__in=mentor_sessions)
            
            # Calculate feedback count and average rating
            feedback_count = feedbacks.count()
            average_rating = feedbacks.aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0
            
            # Get serialized data
            serialized_mentor = MentorListSerializer(mentor).data
            
            # Add feedback data
            serialized_mentor['feedback_count'] = feedback_count
            serialized_mentor['average_rating'] = average_rating
            
            mentor_data.append(serialized_mentor)
        
        return Response(mentor_data, status=status.HTTP_200_OK)
            
    except MenteeProfile.DoesNotExist:
        return Response(
            {"message": "Mentee profile not found"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"message": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def notification_list(request):
    """
    List notifications for the current user.
    For admin users, show all notifications.
    For regular users, show only their notifications.
    """
    if request.user.is_staff:
        notifications = Notification.objects.all()
        # If type parameter is provided, filter by type
        notification_type = request.query_params.get('type')
        if notification_type:
            notifications = notifications.filter(type=notification_type)
    else:
        notifications = Notification.objects.filter(user=request.user)
    
    notifications = notifications.order_by('-created_at')
    serializer = NotificationSerializer(notifications, many=True)
    return Response(serializer.data)

@api_view(['GET', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
def notification_detail(request, pk):
    """
    Retrieve, update, or delete a notification.
    """
    try:
        notification = Notification.objects.get(pk=pk)
    except Notification.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    # Only allow users to access their own notifications (except for admins)
    if not request.user.is_staff and notification.user != request.user:
        return Response(status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        serializer = NotificationSerializer(notification)
        return Response(serializer.data)

    elif request.method == 'PATCH':
        serializer = NotificationSerializer(notification, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        notification.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_notification(request):
    """
    Create a new notification.
    """
    serializer = NotificationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_all_read(request):
    """
    Mark all notifications as read for the current user.
    """
    if request.user.is_staff:
        Notification.objects.all().update(is_read=True)
    else:
        Notification.objects.filter(user=request.user).update(is_read=True)
    return Response({"message": "All notifications marked as read"})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_unread_notification_count(request):
    """
    Get the count of unread notifications for the current user.
    """
    try:
        count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).count()
        return Response({'count': count})
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user

    if request.method == 'GET':
        try:
            if hasattr(user, 'mentorprofile'):
                profile = user.mentorprofile
                serializer = MentorProfileSerializer(profile)
            elif hasattr(user, 'menteeprofile'):
                profile = user.menteeprofile
                serializer = MenteeProfileSerializer(profile)
            else:
                return Response({'message': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
            
            return Response(serializer.data)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'PUT':
        try:
            # Determine profile type
            if hasattr(user, 'mentorprofile'):
                profile = user.mentorprofile
                is_mentor = True
            elif hasattr(user, 'menteeprofile'):
                profile = user.menteeprofile
                is_mentor = False
            else:
                return Response({'message': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

            # Handle user data update
            user_data = request.data.get('user_data')
            if user_data:
                if isinstance(user_data, str):
                    user_data = json.loads(user_data)
                user.first_name = user_data.get('first_name', user.first_name)
                user.last_name = user_data.get('last_name', user.last_name)
                user.email = user_data.get('email', user.email)
                user.save()

            # Handle profile image
            if 'profile_image' in request.FILES:
                try:
                    # Delete old profile image if it exists
                    if profile.profile_image:
                        old_image_path = os.path.join(settings.MEDIA_ROOT, str(profile.profile_image))
                        try:
                            if os.path.isfile(old_image_path):
                                os.remove(old_image_path)
                        except Exception as e:
                            print(f"Error deleting old profile image: {str(e)}")
                    
                    # Set new profile image
                    profile.profile_image = request.FILES['profile_image']
                except Exception as e:
                    print(f"Error handling profile image: {str(e)}")

            # Update basic profile fields
            basic_fields = ['bio', 'designation', 'location', 'linkedin_url', 'github_url']
            for field in basic_fields:
                if field in request.data:
                    setattr(profile, field, request.data.get(field))

            # Handle skills
            if 'skills' in request.data:
                try:
                    skills_data = json.loads(request.data['skills'])
                    if isinstance(skills_data, list):
                        profile.skills.clear()
                        skill_objects = Skill.objects.filter(id__in=skills_data)
                        profile.skills.add(*skill_objects)
                except json.JSONDecodeError:
                    pass

            # Handle mentor-specific fields
            if is_mentor:
                mentor_fields = ['company', 'experience_years', 'hourly_rate', 'website']
                for field in mentor_fields:
                    if field in request.data:
                        if field == 'hourly_rate':
                            try:
                                value = request.data.get(field)
                                if value:
                                    setattr(profile, field, float(value))
                            except (ValueError, TypeError):
                                pass
                        else:
                            setattr(profile, field, request.data.get(field))

                # Handle availability
                if 'availability' in request.data:
                    try:
                        availability_data = json.loads(request.data['availability'])
                        # Clear existing availability
                        profile.availability.all().delete()
                        
                        # Create new availability entries
                        for day, times in availability_data.items():
                            if times.get('available'):
                                MentorAvailability.objects.create(
                                    mentor=profile,
                                    day_of_week=day,
                                    start_time=times.get('start_time', '09:00'),
                                    end_time=times.get('end_time', '17:00'),
                                    is_recurring=True
                                )
                    except json.JSONDecodeError:
                        pass

            # Save the profile
            profile.save()

            # Return updated profile with fresh data
            if is_mentor:
                profile.refresh_from_db()  # Refresh from database to get updated data
                serializer = MentorProfileSerializer(profile)
            else:
                profile.refresh_from_db()  # Refresh from database to get updated data
                serializer = MenteeProfileSerializer(profile)

            return Response(serializer.data)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    try:
        user = request.user
        data = request.data
        
        if not user.check_password(data.get('old_password')):
            return Response(
                {"message": "Current password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if data.get('new_password') != data.get('confirm_password'):
            return Response(
                {"message": "New passwords do not match"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        user.set_password(data.get('new_password'))
        user.save()
        
        return Response(
            {"message": "Password updated successfully"},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        return Response(
            {"message": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    try:
        if not request.user.is_staff:
            return Response(
                {"message": "Unauthorized access"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        # Sort mentors and mentees by registration date (newest first)
        mentors = MentorProfile.objects.select_related('user').prefetch_related('skills', 'availability').order_by('-user__date_joined')
        mentees = MenteeProfile.objects.select_related('user').prefetch_related('skills').order_by('-user__date_joined')
        
        mentor_serializer = MentorListSerializer(mentors, many=True)
        mentee_serializer = MenteeProfileSerializer(mentees, many=True)
        
        return Response({
            "mentors": mentor_serializer.data,
            "mentees": mentee_serializer.data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {"message": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

class MentorshipRequestViewSet(viewsets.ModelViewSet):
    serializer_class = MentorshipRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.user_type == 'mentor':
            return MentorshipRequest.objects.filter(mentor=user.mentorprofile)
        else:
            return MentorshipRequest.objects.filter(mentee=user.menteeprofile)

    def create(self, request, *args, **kwargs):
        mentor_id = request.data.get('mentor_id')
        message = request.data.get('message')
        
        if not mentor_id or not message:
            return Response(
                {'error': 'mentor_id and message are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            mentor = MentorProfile.objects.get(id=mentor_id)
            mentee = request.user.menteeprofile

            # Check if there's already a pending or accepted request
            existing_request = MentorshipRequest.objects.filter(
                mentor=mentor,
                mentee=mentee,
                status__in=['Pending', 'Accepted']
            ).first()

            if existing_request:
                return Response(
                    {
                        'error': f'You already have a {existing_request.status.lower()} request with this mentor. ' +
                                'You can request again after the current request is rejected or completed.'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create the request
            request_data = {
                'mentor_id': mentor.id,
                'mentee_id': mentee.id,
                'message': message,
                'status': 'Pending'
            }
            serializer = self.get_serializer(data=request_data)
            serializer.is_valid(raise_exception=True)
            mentorship_request = serializer.save()

            # Create notification for the mentor
            Notification.objects.create(
                user=mentor.user,
                type='request',
                content=f'New mentorship request from {mentee.user.get_full_name() or mentee.user.email}',
                related_id=mentorship_request.id
            )

            # Send email to mentor
            context = {
                'recipient_name': mentor.user.get_full_name() or mentor.user.email,
                'mentee_name': mentee.user.get_full_name() or mentee.user.email,
                'message': message,
                'request_url': f"{settings.FRONTEND_URL}/mentor/requests"
            }
            send_mail(
                subject='New Mentorship Request',
                message='',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[mentor.user.email],
                html_message=render_to_string('email/new_connection_request.html', context)
            )

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except MentorProfile.DoesNotExist:
            return Response(
                {'error': 'Mentor not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['patch'])
    def update_status(self, request, pk=None):
        request_obj = self.get_object()
        new_status = request.data.get('status')

        if not new_status or new_status not in ['Accepted', 'Rejected']:
            return Response(
                {'error': 'Invalid status. Must be either "Accepted" or "Rejected"'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Only mentor can update the status
        if request.user.user_type != 'mentor':
            return Response(
                {'error': 'Only mentors can update request status'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            request_obj.status = new_status.title()
            request_obj.save()

            # If request is accepted, create a mentorship relationship
            if new_status.title() == 'Accepted':
                # Check if relationship already exists
                existing_relationship = MentorshipRelationship.objects.filter(
                    mentor=request_obj.mentor,
                    mentee=request_obj.mentee,
                    status='Active'
                ).exists()

                if not existing_relationship:
                    MentorshipRelationship.objects.create(
                        mentor=request_obj.mentor,
                        mentee=request_obj.mentee,
                        request=request_obj,
                        status='Active',
                        start_date=timezone.now().date()
                    )

            return Response(self.get_serializer(request_obj).data)
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def pending_requests(self, request):
        if request.user.user_type != 'mentor':
            return Response(
                {'error': 'Only mentors can view pending requests'},
                status=status.HTTP_403_FORBIDDEN
            )

        requests = MentorshipRequest.objects.filter(
            mentor=request.user.mentorprofile,
            status='Pending'
        )
        serializer = self.get_serializer(requests, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def my_requests(self, request):
        if request.user.user_type != 'mentee':
            return Response(
                {'error': 'Only mentees can view their requests'},
                status=status.HTTP_403_FORBIDDEN
            )

        requests = MentorshipRequest.objects.filter(
            mentee=request.user.menteeprofile
        )
        serializer = self.get_serializer(requests, many=True)
        return Response(serializer.data)

class MentorshipRelationshipViewSet(viewsets.ModelViewSet):
    serializer_class = MentorshipRelationshipSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.user_type == 'mentor':
            return MentorshipRelationship.objects.filter(mentor=user.mentorprofile)
        else:
            return MentorshipRelationship.objects.filter(mentee=user.menteeprofile)

    @action(detail=False, methods=['get'])
    def active(self, request):
        if request.user.user_type != 'mentor':
            return Response(
                {'error': 'Only mentors can view their active mentees'},
                status=status.HTTP_403_FORBIDDEN
            )

        relationships = MentorshipRelationship.objects.filter(
            mentor=request.user.mentorprofile,
            status='Active'
        ).select_related('mentee', 'mentee__user').prefetch_related('mentee__skills')

        mentees = []
        for rel in relationships:
            mentee_data = MenteeProfileSerializer(rel.mentee).data
            mentees.append(mentee_data)

        return Response(mentees)

@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def set_hourly_rate(request, mentor_id):
    """
    Admin endpoint to set hourly rate for a mentor.
    """
    try:
        mentor = MentorProfile.objects.get(id=mentor_id)
    except MentorProfile.DoesNotExist:
        return Response(
            {'message': 'Mentor not found'},
            status=status.HTTP_404_NOT_FOUND
        )

    hourly_rate = request.data.get('hourly_rate')
    if not hourly_rate:
        return Response(
            {'message': 'Hourly rate is required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        hourly_rate = float(hourly_rate)
        if hourly_rate < 0:
            return Response(
                {'message': 'Hourly rate must be a positive number'},
                status=status.HTTP_400_BAD_REQUEST
            )
    except ValueError:
        return Response(
            {'message': 'Invalid hourly rate format'},
            status=status.HTTP_400_BAD_REQUEST
        )

    mentor.hourly_rate = hourly_rate
    mentor.save()

    return Response(
        {'message': 'Hourly rate updated successfully',
         'hourly_rate': hourly_rate},
        status=status.HTTP_200_OK
    )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_mentor_profile(request):
    """
    Create a new mentor profile for the authenticated user.
    """
    if request.user.user_type != 'mentor':
        return Response(
            {'message': 'Only mentors can create mentor profiles'},
            status=status.HTTP_403_FORBIDDEN
        )

    try:
        # First, create the mentor profile
        serializer = MentorProfileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        mentor_profile = serializer.save(user=request.user)

        # Add skills to mentor_profile_skills table
        skills = request.data.getlist('skills')
        if skills:
            mentor_profile.skills.set(skills)

        # Add availability to mentor_availability table
        availability_data = request.data.getlist('availability')
        if availability_data:
            for avail_str in availability_data:
                try:
                    avail_data = json.loads(avail_str)
                    MentorAvailability.objects.create(
                        mentor=mentor_profile,
                        day_of_week=avail_data['day_of_week'],
                        start_time=avail_data['start_time'],
                        end_time=avail_data['end_time'],
                        is_recurring=avail_data.get('is_recurring', True)
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    continue  # Skip invalid availability data

        # Create notification for admins
        admin_users = User.objects.filter(user_type='admin')
        for admin in admin_users:
            Notification.objects.create(
                user=admin,
                type='system',
                content=f'New mentor {request.user.first_name} {request.user.last_name} has registered. Please review their profile and set their hourly rate.',
                related_id=mentor_profile.id
            )

        # Set profile_completed to True
        request.user.profile_completed = True
        request.user.save()

        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED
        )

    except Exception as e:
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_mentee_profile(request, pk):
    """
    Get a specific mentee profile by ID.
    """
    try:
        mentee_profile = MenteeProfile.objects.get(id=pk)
        
        # Check if the user has permission to view this profile
        if request.user.user_type == 'admin':
            # Admins can view any profile
            has_permission = True
        elif request.user.id == mentee_profile.user_id:
            # Mentees can view their own profile
            has_permission = True
        elif request.user.user_type == 'mentor':
            # Mentors can view profiles of mentees who have requested mentorship from them
            has_permission = MentorshipRequest.objects.filter(
                mentor=request.user.mentorprofile,
                mentee=mentee_profile
            ).exists()
        else:
            has_permission = False

        if has_permission:
            serializer = MenteeProfileSerializer(mentee_profile)
            
            # Get counts for mentorship requests and relationships
            pending_requests = MentorshipRequest.objects.filter(
                mentee=mentee_profile,
                status='Pending'
            )
            
            pending_requests_count = pending_requests.count()
            
            active_mentorships_count = MentorshipRelationship.objects.filter(
                mentee=mentee_profile,
                status='Active'
            ).count()
            
            # Add counts to the response
            response_data = serializer.data
            response_data['pending_requests_count'] = pending_requests_count
            response_data['active_mentorships_count'] = active_mentorships_count
            
            return Response(response_data)
        else:
            return Response(
                {'message': 'You do not have permission to view this profile'},
                status=status.HTTP_403_FORBIDDEN
            )
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'Mentee profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_mentor_availability(request, mentor_id):
    """
    Get available slots for a mentor.
    """
    try:
        # Get mentor profile
        mentor = MentorProfile.objects.get(id=mentor_id)
        
        # Get all availability entries for this mentor
        availability = MentorAvailability.objects.filter(mentor=mentor)
        
        # Format the availability data
        available_slots = []
        for avail in availability:
            slot = {
                'day': avail.day_of_week,
                'start_time': avail.start_time.isoformat(),
                'end_time': avail.end_time.isoformat(),
                'is_recurring': avail.is_recurring
            }
            available_slots.append(slot)
        
        return Response({
            'available_slots': available_slots
        }, status=status.HTTP_200_OK)
        
    except MentorProfile.DoesNotExist:
        return Response(
            {'message': 'Mentor not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_booking_order(request):
    """
    Create a Razorpay order for booking a mentor session.
    """
    try:
        data = json.loads(request.body)
        mentor_id = data.get('mentor_id')
        time_slot = data.get('time_slot')
        amount = data.get('amount')
        
        print('Received booking data:', {
            'mentor_id': mentor_id,
            'time_slot': time_slot,
            'amount': amount
        })
        
        if not mentor_id or not time_slot or not amount:
            return Response(
                {'message': 'Invalid booking data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get mentor details
        mentor = MentorProfile.objects.get(id=mentor_id)
        
        # Validate amount
        try:
            amount = Decimal(amount)
            if amount <= 0:
                return Response(
                    {'message': 'Amount must be greater than zero'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except (TypeError, ValueError) as e:
            print('Amount validation error:', str(e))
            return Response(
                {'message': 'Invalid amount format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Convert amount to paise (multiply by 100)
        amount_paise = int(amount * 100)
        print('Amount in paise:', amount_paise)
        
        # Create Razorpay order
        try:
            order = razorpay_client.order.create({
                'amount': amount_paise,
                'currency': 'INR',
                'payment_capture': 1  # Auto-capture payment
            })
            print('Razorpay order created:', order)
            
            return Response({
                'order_id': order['id'],
                'amount': amount_paise,
                'currency': 'INR'
            }, status=status.HTTP_200_OK)
                
        except Exception as e:
            print('Razorpay order creation error:', str(e))
            return Response(
                {'message': f'Failed to create payment order: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    except MentorProfile.DoesNotExist:
        return Response(
            {'message': 'Mentor not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Create order error:', str(e))
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    try:
        data = json.loads(request.body)
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')
        booking_data = data.get('booking_data')
        
        if not booking_data:
            return Response(
                {'message': 'Booking data not provided'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify payment signature
        params_dict = {
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_order_id': razorpay_order_id,
            'razorpay_signature': razorpay_signature
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
        except Exception as e:
            return Response(
                {'message': 'Payment verification failed: ' + str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get mentor and mentee details
        mentor_id = booking_data.get('mentor_id')
        time_slot = booking_data.get('time_slot')
        amount = booking_data.get('amount')
        
        if not mentor_id or not time_slot or not amount:
            return Response(
                {'message': 'Invalid booking data'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            mentor = MentorProfile.objects.get(id=mentor_id)
        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'Mentor not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            mentee = MenteeProfile.objects.get(user=request.user)
        except MenteeProfile.DoesNotExist:
            return Response(
                {'message': 'Mentee profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create or get mentorship relationship
        relationship, created = MentorshipRelationship.objects.get_or_create(
            mentee=mentee,
            mentor=mentor,
            defaults={'status': 'Active'}
        )
        
        # Create payment record
        payment_data = {
            'mentee_id': mentee.id,
            'mentor_id': mentor.id,
            'amount': Decimal(amount),
            'status': 'Completed'
        }
        
        payment_serializer = PaymentSerializer(data=payment_data)
        
        if not payment_serializer.is_valid():
            print('Payment serializer errors:', payment_serializer.errors)
            return Response(
                {'message': 'Invalid payment data', 'errors': payment_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        payment = payment_serializer.save()
        
        # Calculate the next occurrence of the selected day
        selected_day = time_slot['day']
        today = datetime.now().date()
        
        # Map abbreviated days to full names
        day_map = {
            'Mon': 'Monday',
            'Tue': 'Tuesday',
            'Wed': 'Wednesday',
            'Thu': 'Thursday',
            'Fri': 'Friday',
            'Sat': 'Saturday',
            'Sun': 'Sunday'
        }
        
        # Get the full day name if abbreviated
        full_day_name = day_map.get(selected_day, selected_day)
        
        # Get the day number (0 = Monday, 6 = Sunday)
        target_day = list(day_map.values()).index(full_day_name)
        current_day = today.weekday()
        
        # Calculate days until next occurrence
        days_ahead = target_day - current_day
        if days_ahead <= 0:  # Target day has passed this week
            days_ahead += 7
            
        # Calculate the next session date
        session_date = today + timedelta(days=days_ahead)
        
        # Parse the selected time
        selected_time = datetime.strptime(time_slot['selected_time'], '%H:%M').time()
        
        # If the selected time has passed for today and it's the same day, schedule for next week
        if session_date == today and selected_time < datetime.now().time():
            session_date += timedelta(days=7)
        
        # Create session booking
        session = Session.objects.create(
            relationship=relationship,
            session_date=session_date,
            start_time=selected_time,
            end_time=(
                datetime.combine(session_date, selected_time) + 
                timedelta(hours=1)
            ).time(),
            status='Pending'
        )
        
        # Update payment with session reference
        payment.session = session
        payment.save()
        
        # Create notification for mentee
        Notification.objects.create(
            user=request.user,
            type='booking',
            content=f'Your session with {mentor.user.first_name} {mentor.user.last_name} has been booked successfully for {session_date.strftime("%B %d, %Y")} at {selected_time.strftime("%I:%M %p")}',
            related_id=session.id
        )

        # Create notification for mentor
        Notification.objects.create(
            user=mentor.user,
            type='booking',
            content=f'New session booked by {request.user.first_name} {request.user.last_name} for {session_date.strftime("%B %d, %Y")} at {selected_time.strftime("%I:%M %p")}',
            related_id=session.id
        )

        # Send email to mentor
        subject = f'New Session Booked - {session_date.strftime("%B %d, %Y")}'
        html_message = render_to_string('email/session_booked.html', {
            'mentor_name': mentor.user.get_full_name(),
            'mentee_name': request.user.get_full_name(),
            'session_date': session_date.strftime("%B %d, %Y"),
            'session_time': selected_time.strftime("%I:%M %p"),
            'amount': amount
        })
        plain_message = strip_tags(html_message)
        
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [mentor.user.email],
            html_message=html_message,
            fail_silently=False
        )
        
        return Response({
            'message': 'Payment successful and session booked',
            'session_id': session.id
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print('Verify payment error:', str(e))
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentee_sessions_list(request):
    """
    List sessions for the current mentee user.
    """
    try:
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Get all sessions where this mentee is involved
        sessions = Session.objects.filter(
            relationship__mentee=mentee_profile
        ).order_by('-session_date', '-start_time')
        
        serializer = SessionSerializer(sessions, many=True)
        return Response(serializer.data)
    
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentee_unread_notification_count(request):
    """
    Get the count of unread notifications for the current mentee user.
    """
    try:
        # Get mentee profile
        mentee = MenteeProfile.objects.get(user=request.user)
        
        # Count unread notifications
        unread_count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).count()
        
        return Response({'count': unread_count}, status=status.HTTP_200_OK)
        
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error fetching unread notification count:', str(e))
        return Response(
            {'message': 'Failed to fetch unread notification count'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentor_notification_list(request):
    """
    List notifications for the current mentor user.
    Shows booking, feedback, session-related notifications and system notifications.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Get all notifications for this mentor
            notifications = Notification.objects.filter(
                user=request.user
            ).order_by('-created_at')
            
            # Add session details to notifications where applicable
            for notification in notifications:
                if notification.type in ['booking', 'feedback', 'session'] and notification.related_id:
                    try:
                        session = Session.objects.get(
                            id=notification.related_id,
                            relationship__mentor=mentor_profile
                        )
                        notification.session_details = {
                            'id': session.id,
                            'session_date': session.session_date,
                            'start_time': session.start_time,
                            'end_time': session.end_time,
                            'status': session.status,
                            'mentee': session.relationship.mentee.user.username
                        }
                    except Session.DoesNotExist:
                        notification.session_details = None
                else:
                    notification.session_details = None
            
            serializer = NotificationSerializer(notifications, many=True)
            return Response(serializer.data)
        
        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentor_sessions_list(request):
    """
    List sessions for the current mentor user.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Get all sessions where this mentor is involved
            sessions = Session.objects.filter(
                relationship__mentor=mentor_profile
            ).order_by('-session_date', '-start_time')
            
            serializer = SessionSerializer(sessions, many=True)
            return Response(serializer.data)
        
        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentor_unread_notification_count(request):
    """
    Get the count of unread notifications for the current mentor user.
    Shows all unread notifications including booking, feedback, session, and system notifications.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Get count of all unread notifications for this mentor
            unread_count = Notification.objects.filter(
                user=request.user,
                is_read=False
            ).count()
            
            return Response({'count': unread_count})
        
        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_session_email(request):
    """
    Send an email to mentee about session scheduling with meeting link.
    Only mentors can use this endpoint.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            session_id = request.data.get('session_id')
            meeting_link = request.data.get('meeting_link')

            if not session_id or not meeting_link:
                return Response(
                    {'message': 'session_id and meeting_link are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                session = Session.objects.get(id=session_id)
                mentee = session.relationship.mentee
                mentor = session.relationship.mentor

                # Format the email content
                subject = f'Session Scheduled with {mentor.user.first_name} {mentor.user.last_name}'
                message = f"""
                Hello {mentee.user.first_name},

                Your session with {mentor.user.first_name} {mentor.user.last_name} has been scheduled.

                Details:
                Date: {session.session_date}
                Time: {session.start_time} - {session.end_time}
                Meeting Link: {meeting_link}

                Please join the meeting at the scheduled time.
                """

                # Send email
                send_mail(
                    subject,
                    message,
                    'anelizabeth62@gmail.com',  # From email
                    [mentee.user.email],  # To email
                    fail_silently=False,
                )

                return Response(
                    {'message': 'Email sent successfully'},
                    status=status.HTTP_200_OK
                )

            except Session.DoesNotExist:
                return Response(
                    {'message': 'Session not found'},
                    status=status.HTTP_404_NOT_FOUND
                )

        except Exception as e:
            print('Error sending session email:', str(e))
            return Response(
                {'message': 'Failed to send email'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )

@api_view(['GET', 'PATCH', 'DELETE'])
@permission_classes([IsAuthenticated])
def session_detail(request, session_id):
    """
    Get, update, or delete a specific session.
    Both mentors and mentees can access this endpoint.
    """
    try:
        # Check if user is a mentor
        is_mentor = hasattr(request.user, 'mentorprofile')
        # Check if user is a mentee
        is_mentee = hasattr(request.user, 'menteeprofile')

        if not (is_mentor or is_mentee):
            return Response(
                {'message': 'User must be either a mentor or mentee'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get the session based on user type
        if is_mentor:
            session = Session.objects.get(
                id=session_id,
                relationship__mentor=request.user.mentorprofile
            )
        else:
            session = Session.objects.get(
                id=session_id,
                relationship__mentee=request.user.menteeprofile
            )

        if request.method == 'GET':
            serializer = SessionSerializer(session)
            return Response(serializer.data)

        elif request.method == 'PATCH':
            if not is_mentor:
                return Response(
                    {'message': 'Only mentors can update sessions'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = SessionSerializer(session, data=request.data, partial=True)
            if serializer.is_valid():
                # Check if this is a cancellation request
                if request.data.get('status') == 'Cancelled':
                    should_delete_payment = request.data.get('should_delete_payment', False)
                    should_notify_mentee = request.data.get('should_notify_mentee', False)
                    
                    # Delete associated payment if it exists
                    if should_delete_payment:
                        try:
                            payment = Payment.objects.filter(session=session).first()
                            if payment:
                                payment.delete()
                        except Exception as e:
                            print('Error deleting payment:', str(e))
                    
                    # Send email to mentee
                    if should_notify_mentee:
                        try:
                            mentee = session.relationship.mentee
                            mentee_email = mentee.user.email
                            mentor_name = f"{request.user.first_name} {request.user.last_name}"
                            session_date = session.session_date.strftime('%B %d, %Y')
                            session_time = session.start_time.strftime('%I:%M %p')
                            
                            subject = 'Session Cancelled - Refund Information'
                            html_message = render_to_string('email/session_cancelled.html', {
                                'mentee_name': mentee.user.get_full_name(),
                                'mentor_name': mentor_name,
                                'session_date': session_date,
                                'session_time': session_time
                            })
                            plain_message = strip_tags(html_message)
                            
                            send_mail(
                                subject,
                                plain_message,
                                settings.DEFAULT_FROM_EMAIL,
                                [mentee_email],
                                html_message=html_message,
                                fail_silently=True
                            )
                            
                            # Create notification for mentee
                            Notification.objects.create(
                                user=mentee.user,
                                type='session',
                                content=f'Your session with {mentor_name} scheduled for {session_date} at {session_time} has been cancelled. Your payment will be refunded shortly.',
                                related_id=session.id
                            )
                        except Exception as e:
                            print('Error sending notification:', str(e))

                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            # Only allow deletion of Cancelled or No-show sessions
            if session.status not in ['Cancelled', 'No-show', 'Completed']:
                return Response(
                    {'message': 'Only Cancelled, No-show, or Completed sessions can be deleted'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Delete associated payment if it exists
            try:
                payment = Payment.objects.filter(session=session).first()
                if payment:
                    payment.delete()
            except Exception as e:
                print('Error deleting payment:', str(e))

            # Delete the session
            session.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

    except (MentorProfile.DoesNotExist, MenteeProfile.DoesNotExist):
        return Response(
            {'message': 'User profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Session.DoesNotExist:
        return Response(
            {'message': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error handling session:', str(e))
        return Response(
            {'message': 'Failed to process request'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mentor_notification_detail(request, pk):
    """
    Update a mentor's notification (mark as read).
    Only mentors can access this endpoint.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Get the notification - just check that it belongs to this user
            notification = Notification.objects.get(
                id=pk,
                user=request.user
            )
            
            # Update the notification
            notification.is_read = request.data.get('is_read', True)
            notification.save()

            return Response(NotificationSerializer(notification).data)

        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
        except Notification.DoesNotExist:
            return Response(
                {'message': 'Notification not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print('Error updating mentor notification:', str(e))
            return Response(
                {'message': 'Failed to update notification'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def mentor_notification_delete(request, pk):
    """
    Delete a mentor's notification.
    Only mentors can access this endpoint.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Get the notification - just check that it belongs to this user
            notification = Notification.objects.get(
                id=pk,
                user=request.user
            )

            # Delete the notification
            notification.delete()

            return Response(
                {'message': 'Notification deleted successfully'}
            )

        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
        except Notification.DoesNotExist:
            return Response(
                {'message': 'Notification not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print('Error deleting mentor notification:', str(e))
            return Response(
                {'message': 'Failed to delete notification'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mentor_mark_all_read(request):
    """
    Mark all notifications as read for the current mentor.
    Only mentors can access this endpoint.
    """
    if not request.user.is_staff:  # Only mentors can access this endpoint
        try:
            mentor_profile = MentorProfile.objects.get(user=request.user)
            
            # Mark all unread notifications as read for this user
            notifications = Notification.objects.filter(
                user=request.user,
                is_read=False
            )

            # Mark all as read
            count = notifications.update(is_read=True)

            return Response(
                {'message': f'{count} notifications marked as read'}
            )

        except MentorProfile.DoesNotExist:
            return Response(
                {'message': 'User is not a mentor'},
                status=status.HTTP_403_FORBIDDEN
            )
        except Exception as e:
            print('Error marking all notifications as read:', str(e))
            return Response(
                {'message': 'Failed to mark notifications as read'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    return Response(
        {'message': 'This endpoint is only for mentors'},
        status=status.HTTP_403_FORBIDDEN
    )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def submit_feedback(request):
    """
    Submit feedback for a session.
    - Save feedback details
    - Send email to mentor
    - Create notification for mentor
    """
    try:
        # Get mentee profile
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Get session and mentor details
        session_id = request.data.get('session_id')
        session = Session.objects.get(id=session_id)
        mentor = session.relationship.mentor
        
        # Create feedback
        feedback = Feedback.objects.create(
            session=session,
            rating=request.data.get('rating'),
            comment=request.data.get('comment')
        )
        
        # Send email to mentor
        subject = f'New Feedback Received for Session {session_id}'
        
        # Render email template
        html_message = render_to_string('email/feedback_notification.html', {
            'mentee_name': mentee_profile.user.get_full_name(),
            'rating': feedback.rating,
            'comment': feedback.comment,
            'session_date': session.session_date,
            'session_time': session.start_time
        })
        
        # Create plain text version of email
        plain_message = strip_tags(html_message)
        
        # Send email
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [mentor.user.email],
            html_message=html_message,
            fail_silently=False
        )
        
        # Format session date
        formatted_date = session.session_date.strftime('%B %d, %Y')
        
        # Create notification for mentor with session date
        Notification.objects.create(
            user=mentor.user,
            content=f'New feedback received from {mentee_profile.user.get_full_name()} for session on {formatted_date}',
            type='feedback',
            related_id=session_id
        )
        
        return Response(
            {
                'message': 'Feedback submitted successfully',
                'feedback_id': feedback.id
            },
            status=status.HTTP_201_CREATED
        )
        
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
        
    except Session.DoesNotExist:
        return Response(
            {'message': 'Session not found'},
            status=status.HTTP_404_NOT_FOUND
        )
        
    except Exception as e:
        print('Error submitting feedback:', str(e))
        return Response(
            {'message': 'Failed to submit feedback'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentee_notification_list(request):
    """
    List notifications for the current mentee user.
    """
    try:
        # Get mentee profile
        mentee = MenteeProfile.objects.get(user=request.user)
        
        # Get notifications for this mentee
        notifications = Notification.objects.filter(
            user=request.user
        ).order_by('-created_at')
        
        # Get related session details for each notification
        notification_data = []
        for notification in notifications:
            notification_info = {
                'id': notification.id,
                'content': notification.content,
                'created_at': notification.created_at,
                'is_read': notification.is_read,
                'type': notification.type
            }
            
            # Only try to get session details if the notification has a related_id and is of type 'session' or 'booking'
            if notification.related_id and notification.type in ['session', 'booking']:
                try:
                    session = Session.objects.get(id=notification.related_id)
                    notification_info['session'] = {
                        'id': session.id,
                        'mentor': {
                            'id': session.relationship.mentor.id,
                            'name': f"{session.relationship.mentor.user.first_name} {session.relationship.mentor.user.last_name}"
                        },
                        'date': session.session_date,
                        'time': session.start_time,
                        'status': session.status
                    }
                except Session.DoesNotExist:
                    # If session doesn't exist, just skip adding session info
                    pass
            
            notification_data.append(notification_info)
        
        return Response(notification_data, status=status.HTTP_200_OK)
        
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error fetching mentee notifications:', str(e))
        return Response(
            {'message': 'Failed to fetch notifications'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_feedback_exists(request, session_id):
    """
    Check if feedback exists for a session.
    Returns true if feedback exists, false otherwise.
    """
    try:
        # Get mentee profile
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Check if feedback exists for this session
        feedback_exists = Feedback.objects.filter(
            session_id=session_id,
            session__relationship__mentee=mentee_profile
        ).exists()
        
        return Response({
            'exists': feedback_exists
        })
        
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error checking feedback:', str(e))
        return Response(
            {'message': 'Failed to check feedback'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentee_dashboard_data(request):
    """
    Get dashboard data for mentee including:
    - Completed sessions count
    - Upcoming sessions count
    - Number of mentors contacted
    """
    try:
        mentee_profile = MenteeProfile.objects.get(user=request.user)

        # Get completed sessions count
        completed_sessions = Session.objects.filter(
            relationship__mentee=mentee_profile,
            status='Completed'
        ).count()

        # Get upcoming (pending) sessions count
        upcoming_sessions = Session.objects.filter(
            relationship__mentee=mentee_profile,
            status='Pending'
        ).count()

        # Get count of mentors contacted (unique mentorship requests)
        mentors_contacted = MentorshipRequest.objects.filter(
            mentee=mentee_profile
        ).values('mentor').distinct().count()

        return Response({
            'completed_sessions': completed_sessions,
            'upcoming_sessions': upcoming_sessions,
            'mentors_contacted': mentors_contacted
        }, status=status.HTTP_200_OK)

    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'Mentee profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error fetching mentee dashboard data:', str(e))
        return Response(
            {'message': 'Failed to fetch dashboard data'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentor_dashboard_data(request):
    """
    Get dashboard data for mentor including:
    - Total sessions count
    - Total earnings
    - Total reviews count
    """
    try:
        mentor_profile = MentorProfile.objects.get(user=request.user)

        # Get all sessions for this mentor
        sessions_count = Session.objects.filter(
            relationship__mentor=mentor_profile
        ).count()

        # Calculate total earnings from payments
        total_earnings = Payment.objects.filter(
            session__relationship__mentor=mentor_profile,
            status='Completed'
        ).aggregate(total=Sum('amount'))['total'] or 0

        # Get count of feedback received
        reviews_count = Feedback.objects.filter(
            session__relationship__mentor=mentor_profile
        ).count()

        return Response({
            'sessions': sessions_count,
            'earnings': f"₹{total_earnings}",  # Using Rupee symbol since we're using INR
            'reviews': reviews_count
        }, status=status.HTTP_200_OK)

    except MentorProfile.DoesNotExist:
        return Response(
            {'message': 'Mentor profile not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error fetching mentor dashboard data:', str(e))
        return Response(
            {'message': 'Failed to fetch dashboard data'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def end_mentorship_relationship(request, user_id):
    """
    End a mentorship relationship between a mentor and mentee.
    Can be called by either mentor or mentee.
    If called by mentee: user_id is mentor_id
    If called by mentor: user_id is mentee_id
    """
    try:
        # Get the reason from the request body
        reason = request.data.get('reason', '')
        
        # Determine if the requester is a mentor or mentee
        is_mentor = hasattr(request.user, 'mentorprofile')
        is_mentee = hasattr(request.user, 'menteeprofile')

        if not (is_mentor or is_mentee):
            return Response(
                {'message': 'User must be either a mentor or mentee'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get the relationship based on who's making the request
        if is_mentor:
            # Mentor is ending connection with mentee (user_id is mentee_id)
            relationship = MentorshipRelationship.objects.get(
                mentor=request.user.mentorprofile,
                mentee_id=user_id,
                status='Active'
            )
            mentor = request.user.mentorprofile
            mentee = relationship.mentee
            ended_by = "mentor"
        else:
            # Mentee is ending connection with mentor (user_id is mentor_id)
            relationship = MentorshipRelationship.objects.get(
                mentee=request.user.menteeprofile,
                mentor_id=user_id,
                status='Active'
            )
            mentor = relationship.mentor
            mentee = request.user.menteeprofile
            ended_by = "mentee"

        # Update the relationship status
        relationship.status = 'Ended'
        relationship.save()

        # Delete any existing mentorship requests between these users
        MentorshipRequest.objects.filter(
            mentor=mentor,
            mentee=mentee
        ).delete()

        # Send email to mentee
        context = {
            'recipient_name': mentee.user.get_full_name() or mentee.user.email,
            'other_party_name': mentor.user.get_full_name() or mentor.user.email,
            'ended_by': ended_by,
            'reason': reason
        }
        send_mail(
            subject='Mentorship Connection Ended',
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[mentee.user.email],
            html_message=render_to_string('email/connection_ended.html', context)
        )

        # Send email to mentor
        context = {
            'recipient_name': mentor.user.get_full_name() or mentor.user.email,
            'other_party_name': mentee.user.get_full_name() or mentee.user.email,
            'ended_by': ended_by,
            'reason': reason
        }
        send_mail(
            subject='Mentorship Connection Ended',
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[mentor.user.email],
            html_message=render_to_string('email/connection_ended.html', context)
        )

        # Create notifications for both users using the existing 'type' field
        Notification.objects.create(
            user=mentee.user,
            type='session',  # Using existing type field
            content=f'Your mentorship connection with {mentor.user.get_full_name() or "your mentor"} has been ended.',
            related_id=relationship.id
        )

        Notification.objects.create(
            user=mentor.user,
            type='session',  # Using existing type field
            content=f'Your mentorship connection with {mentee.user.get_full_name() or "your mentee"} has been ended.',
            related_id=relationship.id
        )

        return Response(status=status.HTTP_204_NO_CONTENT)

    except MentorshipRelationship.DoesNotExist:
        return Response(
            {'message': 'No active relationship found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error ending mentorship relationship:', str(e))
        return Response(
            {'message': 'Failed to end mentorship relationship'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_active_mentors_for_mentee(request):
    """
    Get all active mentors for the current mentee.
    """
    try:
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Get active relationships for this mentee
        relationships = MentorshipRelationship.objects.filter(
            mentee=mentee_profile,
            status='Active'
        ).select_related('mentor', 'mentor__user').prefetch_related('mentor__skills')

        mentors = []
        for rel in relationships:
            mentor = rel.mentor
            # Get all sessions for this mentor
            mentor_sessions = Session.objects.filter(relationship__mentor=mentor)
            
            # Get all feedbacks for these sessions
            feedbacks = Feedback.objects.filter(session__in=mentor_sessions)
            
            # Calculate feedback count and average rating
            feedback_count = feedbacks.count()
            average_rating = feedbacks.aggregate(avg_rating=Avg('rating'))['avg_rating'] or 0
            
            # Get serialized data
            mentor_data = MentorListSerializer(mentor).data
            
            # Add feedback data
            mentor_data['feedback_count'] = feedback_count
            mentor_data['average_rating'] = average_rating
            
            mentors.append(mentor_data)

        return Response(mentors, status=status.HTTP_200_OK)
        
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error fetching active mentors:', str(e))
        return Response(
            {'message': 'Failed to fetch mentors'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def mentee_notification_detail(request, pk):
    """
    Update a mentee's notification (mark as read).
    Only mentees can access this endpoint.
    """
    try:
        # Get mentee profile
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Get the notification
        notification = Notification.objects.get(
            id=pk,
            user=request.user
        )

        # Update the notification
        notification.is_read = request.data.get('is_read', True)
        notification.save()

        return Response(NotificationSerializer(notification).data)

    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Notification.DoesNotExist:
        return Response(
            {'message': 'Notification not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error updating mentee notification:', str(e))
        return Response(
            {'message': 'Failed to update notification'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def mentee_notification_delete(request, pk):
    """
    Delete a mentee's notification.
    Only mentees can access this endpoint.
    """
    try:
        # Get mentee profile
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Get the notification
        notification = Notification.objects.get(
            id=pk,
            user=request.user
        )

        # Delete the notification
        notification.delete()

        return Response(
            {'message': 'Notification deleted successfully'},
            status=status.HTTP_200_OK
        )

    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Notification.DoesNotExist:
        return Response(
            {'message': 'Notification not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print('Error deleting mentee notification:', str(e))
        return Response(
            {'message': 'Failed to delete notification'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mentee_mark_all_read(request):
    """
    Mark all notifications as read for the current mentee user.
    """
    try:
        # Get mentee profile
        mentee_profile = MenteeProfile.objects.get(user=request.user)
        
        # Update all unread notifications for this user
        updated_count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).update(is_read=True)
        
        return Response({
            'message': f'{updated_count} notifications marked as read',
            'count': updated_count
        })
    
    except MenteeProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentee'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error marking all notifications as read:', str(e))
        return Response(
            {'message': 'Failed to update notifications'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mentor_feedbacks(request):
    """
    Get all feedbacks for the current mentor.
    """
    try:
        # Get mentor profile
        mentor_profile = MentorProfile.objects.get(user=request.user)
        
        # Get all sessions where this mentor is involved
        mentor_sessions = Session.objects.filter(
            relationship__mentor=mentor_profile
        )
        
        # Get all feedbacks for these sessions - order by session date instead of created_at
        feedbacks = Feedback.objects.filter(
            session__in=mentor_sessions
        ).order_by('-session__session_date')
        
        # Prepare detailed feedback data
        feedback_data = []
        for feedback in feedbacks:
            session = feedback.session
            mentee = session.relationship.mentee
            mentee_user = mentee.user
            
            feedback_info = {
                'id': feedback.id,
                'rating': feedback.rating,
                'comment': feedback.comment,
                'session_id': session.id,
                'session_date': session.session_date,
                'session_time': session.start_time.strftime('%H:%M'),
                'session_topic': session.topic if hasattr(session, 'topic') else None,
                'mentee_id': mentee.id,
                'mentee_name': f"{mentee_user.first_name} {mentee_user.last_name}",
                'mentee_image': mentee.profile_image.url if mentee.profile_image else None
            }
            
            feedback_data.append(feedback_info)
        
        return Response(feedback_data, status=status.HTTP_200_OK)
        
    except MentorProfile.DoesNotExist:
        return Response(
            {'message': 'User is not a mentor'},
            status=status.HTTP_403_FORBIDDEN
        )
    except Exception as e:
        print('Error fetching mentor feedbacks:', str(e))
        return Response(
            {'message': 'Failed to fetch feedbacks'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    """
    Reset a user's password by sending a 6-digit code to their email.
    The code also becomes their temporary password.
    """
    try:
        email = request.data.get('email')
        if not email:
            return Response(
                {'message': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if a user with this email exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'message': 'No account found with this email address'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Generate a 6-digit code
        reset_code = ''.join(random.choices('0123456789', k=6))
        
        # Update the user's password with the 6-digit code
        user.set_password(reset_code)
        user.save()
        
        # Send the email with the reset code
        subject = 'MentorQuest Password Reset'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = user.email
        
        context = {
            'user': user,
            'reset_code': reset_code
        }
        
        html_message = render_to_string('email/password_reset.html', context)
        plain_message = strip_tags(html_message)
        
        send_mail(subject, plain_message, from_email, [to_email], html_message=html_message)
        
        return Response(
            {'message': 'A reset code has been sent to your email'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        print('Password reset error:', str(e))
        return Response(
            {'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_reports(request):
    """
    Return statistics for the admin reports dashboard
    """
    try:
        # User statistics
        mentor_count = MentorProfile.objects.count()
        mentee_count = MenteeProfile.objects.count()
        
        # Mentorship request statistics
        pending_requests = MentorshipRequest.objects.filter(status='Pending').count()
        accepted_requests = MentorshipRequest.objects.filter(status='Accepted').count()
        rejected_requests = MentorshipRequest.objects.filter(status='Rejected').count()
        
        # Session statistics
        pending_sessions = Session.objects.filter(status='Pending').count()
        scheduled_sessions = Session.objects.filter(status='Scheduled').count()
        completed_sessions = Session.objects.filter(status='Completed').count()
        cancelled_sessions = Session.objects.filter(status='Cancelled').count()
        no_show_sessions = Session.objects.filter(status='No-show').count()
        
        return Response({
            'user_stats': {
                'mentor_count': mentor_count,
                'mentee_count': mentee_count
            },
            'request_stats': {
                'pending_count': pending_requests,
                'accepted_count': accepted_requests,
                'rejected_count': rejected_requests
            },
            'session_stats': {
                'pending_count': pending_sessions,
                'scheduled_count': scheduled_sessions,
                'completed_count': completed_sessions,
                'cancelled_count': cancelled_sessions,
                'no_show_count': no_show_sessions
            }
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print('Error fetching admin reports:', str(e))
        return Response(
            {'message': 'Failed to fetch report data'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_request_status_email(request):
    """
    Send email notification to mentee about request status update
    """
    try:
        data = request.data
        recipient_email = data.get('recipient_email')
        recipient_name = data.get('recipient_name')
        mentor_name = data.get('mentor_name')
        request_status = data.get('status')
        message = data.get('message')
        mentee_id = data.get('mentee_id')

        if not all([recipient_email, recipient_name, mentor_name, request_status]):
            return Response(
                {'error': 'Missing required fields'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare email context
        context = {
            'recipient_name': recipient_name,
            'mentor_name': mentor_name,
            'status': request_status,
            'message': message
        }

        # Send email
        send_mail(
            subject=f'Mentorship Request {request_status}',
            message='',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient_email],
            html_message=render_to_string('email/request_status_update.html', context)
        )
        
        return Response(
            {'message': 'Email notification sent successfully'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        print(f"Error in send_request_status_email: {str(e)}")
        return Response(
            {'message': 'Failed to send email notification'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def check_existing_sessions(request):
    """
    Check if there are any existing sessions for a mentor at a given date and time.
    """
    try:
        data = request.data
        mentor_id = data.get('mentor_id')
        session_date = data.get('session_date')
        session_time = data.get('session_time')

        if not all([mentor_id, session_date, session_time]):
            return Response(
                {'message': 'Missing required fields'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Convert session_time to datetime.time object
        try:
            session_time = datetime.strptime(session_time, '%H:%M').time()
        except ValueError:
            return Response(
                {'message': 'Invalid time format'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for existing sessions
        existing_sessions = Session.objects.filter(
            relationship__mentor_id=mentor_id,
            session_date=session_date,
            start_time=session_time,
            status='Pending'
        ).exists()

        return Response({
            'has_conflict': existing_sessions
        }, status=status.HTTP_200_OK)

    except Exception as e:
        print('Error checking existing sessions:', str(e))
        return Response(
            {'message': 'Failed to check existing sessions'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
