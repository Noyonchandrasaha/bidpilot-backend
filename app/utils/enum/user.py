from enum import Enum

# -----------------------------------
# User Role
# -----------------------------------
class UserRole(str, Enum):
    ADMIN = "admin"
    STAFF = "staff"
    VIEWER = "viewer"
