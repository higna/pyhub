from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission


class Beneficiary(AbstractUser):
    Role_Choices = [
        ("user", "User"),
        ("admin", "Admin"),
        ("superadmin", "Super Admin"),
    ]
    role = models.CharField(max_length=20, choices=Role_Choices, default="user")
    requested_role = models.CharField(
        max_length=20, choices=Role_Choices, null=True, blank=True
    )
    email_verified = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    groups = models.ManyToManyField(
        Group,
        related_name="beneficiary_set",
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups",
        related_query_name="beneficiary",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name="beneficiary_set",
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
        related_query_name="beneficiary",
    )

    # User request admin
    def request_admin(self, admin_choice):
        valid_roles = ["admin", "superadmin"]
        if admin_choice not in valid_roles:
            raise ValueError("Invalid role requested. Must be 'admin' or 'superadmin'.")
        if self.role == admin_choice:
            raise ValueError(f"You are already a {admin_choice}.")
        if self.requested_role == admin_choice and not self.is_approved:
            raise ValueError(
                f"You have already requested {admin_choice}. Please wait for approval."
            )
        self.requested_role = admin_choice
        self.is_approved = False  # Reset approval
        self.save()

    # Approve user role
    def approve_role(self, approver):
        valid_roles = ["admin", "superadmin"]
        if approver.role not in valid_roles:
            raise PermissionError(
                "You do not have the permission to approve this request."
            )
        if self.requested_role and self.is_verified:
            if self.requested_role == "superadmin" and approver.role != "superadmin":
                raise PermissionError(
                    "You do not have the permission to approve this request."
                )
            self.role = self.requested_role
            self.requested_role = None
            self.is_approved = True
            self.save()
            return True
        return False

    # Pending Requests
    @property
    def pending_request(self):
        return self.requested_role is not None and not self.is_approved

    # Check admin
    @property
    def is_admin(self):
        return self.role in ["admin", "superadmin"]

    # Display role
    def display_status(self):
        if self.pending_request():
            return f"Requested-{self.get_requested_role_display()}"
        return self.get_role_display()

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
