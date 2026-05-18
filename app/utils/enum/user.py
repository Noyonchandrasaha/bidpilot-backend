from enum import Enum

# -----------------------------------
# User Role
# -----------------------------------
class UserRole(str, Enum):
    ADMIN="ADMIN"
    STUDENT="STUDENT"