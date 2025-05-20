from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinValueValidator, URLValidator, MaxValueValidator

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('user_type', 'admin')  # Set user_type to admin for superusers
        extra_fields.setdefault('profile_completed', True)  # Admin profiles are always complete
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    """
    Extended User model for authentication and basic user information.
    """
    USER_TYPE_CHOICES = (
        ('admin', 'Admin'),
        ('mentor', 'Mentor'),
        ('mentee', 'Mentee'),
    )

    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES, default='mentee')
    email = models.EmailField(unique=True)
    profile_completed = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()
    
    # Required fields from AbstractUser that we're explicitly defining for clarity
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    
    class Meta:
        db_table = 'auth_user'
        
    def __str__(self):
        return f"{self.username} ({self.get_user_type_display()})"

    def save(self, *args, **kwargs):
        # Ensure admin users have profile_completed set to True
        if self.is_staff or self.is_superuser or self.user_type.lower() == 'admin':
            self.profile_completed = True
            self.user_type = 'admin'
        super().save(*args, **kwargs)


class Skill(models.Model):
    skill_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.skill_name


class BaseProfile(models.Model):
    """
    Abstract base model for shared profile fields between mentors and mentees
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="%(class)s")
    profile_image = models.ImageField(upload_to='profile_images', null=True, blank=True)
    bio = models.TextField(blank=True)
    designation = models.CharField(max_length=255)
    skills = models.ManyToManyField(Skill)
    location = models.CharField(max_length=255, blank=True)
    linkedin_url = models.URLField(validators=[URLValidator()], blank=True)
    github_url = models.URLField(validators=[URLValidator()], blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class MenteeProfile(BaseProfile):
    """
    Profile model for mentees with specific fields
    """
    EXPERIENCE_LEVEL_CHOICES = (
        ('Beginner', 'Beginner'),
        ('Intermediate', 'Intermediate'),
        ('Advanced', 'Advanced'),
    )
    
    experience_level = models.CharField(max_length=20, choices=EXPERIENCE_LEVEL_CHOICES, default='Beginner')

    class Meta:
        db_table = 'mentee_profile'
        
    def __str__(self):
        return f"Mentee: {self.user.username}"


class MentorProfile(BaseProfile):
    """
    Profile model for mentors with specific fields
    """
    company = models.CharField(max_length=255)
    experience_years = models.CharField(max_length=10)  # Storing as string for ranges like "1-3", "4-6", etc.
    hourly_rate = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        validators=[MinValueValidator(0)],
        null=False,
        default=0.00
    )
    website = models.URLField(validators=[URLValidator()], blank=True)

    class Meta:
        db_table = 'mentor_profile'
        
    def __str__(self):
        return f"Mentor: {self.user.username}"


class MentorAvailability(models.Model):
    DAYS_OF_WEEK = [
        ('Monday', 'Monday'), ('Tuesday', 'Tuesday'), ('Wednesday', 'Wednesday'),
        ('Thursday', 'Thursday'), ('Friday', 'Friday'), ('Saturday', 'Saturday'),
        ('Sunday', 'Sunday')
    ]
    
    mentor = models.ForeignKey(MentorProfile, on_delete=models.CASCADE, related_name='availability')
    day_of_week = models.CharField(max_length=10, choices=DAYS_OF_WEEK)
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_recurring = models.BooleanField(default=True)

    class Meta:
        db_table = 'mentor_availability'

    def __str__(self):
        return f"{self.mentor.user.username} - {self.day_of_week} ({self.start_time} - {self.end_time})"


class MentorshipRequest(models.Model):
    """
    Mentorship Requests for mentor-mentee matching
    """
    mentee = models.ForeignKey(MenteeProfile, on_delete=models.CASCADE, related_name='requests')
    mentor = models.ForeignKey(MentorProfile, on_delete=models.CASCADE, related_name='requests')
    status = models.CharField(
        max_length=10, 
        choices=[
            ('Pending', 'Pending'), 
            ('Accepted', 'Accepted'), 
            ('Rejected', 'Rejected'), 
            ('Completed', 'Completed')
        ], 
        default='Pending'
    )
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'mentorship_requests'

    def __str__(self):
        return f"Request from {self.mentee.user.username} to {self.mentor.user.username}"


class MentorshipRelationship(models.Model):
    """
    Active mentorship relationships
    """
    mentee = models.ForeignKey(MenteeProfile, on_delete=models.CASCADE)
    mentor = models.ForeignKey(MentorProfile, on_delete=models.CASCADE)
    request = models.ForeignKey(MentorshipRequest, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=10, 
        choices=[
            ('Active', 'Active'), 
            ('Paused', 'Paused'), 
            ('Completed', 'Completed'), 
            ('Terminated', 'Terminated')
        ], 
        default='Active'
    )
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    goals = models.TextField(blank=True)

    class Meta:
        db_table = 'mentorship_relationships'

    def __str__(self):
        return f"Relationship between {self.mentee.user.username} and {self.mentor.user.username}"


class Session(models.Model):
    """Scheduled mentorship sessions"""
    relationship = models.ForeignKey(MentorshipRelationship, on_delete=models.CASCADE)
    session_date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    status = models.CharField(
        max_length=10, 
        choices=[
            ('Pending', 'Pending'),
            ('Scheduled', 'Scheduled'), 
            ('Completed', 'Completed'), 
            ('Cancelled', 'Cancelled'), 
            ('No-show', 'No-show')
        ], 
        default='Pending'
    )

    class Meta:
        db_table = 'sessions'

    def __str__(self):
        return f"Session with {self.relationship.mentor.user.first_name} {self.relationship.mentor.user.last_name} on {self.session_date}"


class Feedback(models.Model):
    """
    Feedback for sessions
    """
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField(blank=True)

    class Meta:
        db_table = 'feedback'

    def __str__(self):
        return f"Feedback for {self.session.session_date} - Rating: {self.rating}"


class Payment(models.Model):
    """Payment transactions"""
    mentee = models.ForeignKey(MenteeProfile, on_delete=models.CASCADE)
    mentor = models.ForeignKey(MentorProfile, on_delete=models.CASCADE)
    session = models.OneToOneField(Session, on_delete=models.CASCADE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    status = models.CharField(
        max_length=15, 
        choices=[
            ('Pending', 'Pending'), 
            ('Completed', 'Completed'), 
            ('Failed', 'Failed')
        ], 
        default='Pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'payments'

    def __str__(self):
        return f"Payment for {self.session_id if self.session_id else 'N/A'}"


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('request', 'Request'),
        ('acceptance', 'Acceptance'),
        ('session', 'Session'),
        ('message', 'Message'),
        ('feedback', 'Feedback'),
        ('system', 'System'),
        ('skill', 'Skill'),  # Added for skill-related notifications
        ('booking', 'Booking')  # Added for booking-related notifications
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type = models.CharField(max_length=15, choices=NOTIFICATION_TYPES)
    content = models.TextField()
    related_id = models.IntegerField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'
        ordering = ['-created_at']  # Most recent notifications first

    def __str__(self):
        return f"{self.get_type_display()} notification for {self.user.username}"