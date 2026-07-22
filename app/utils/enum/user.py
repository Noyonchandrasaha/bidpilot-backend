from enum import Enum

# -----------------------------------
# User Role
# -----------------------------------
class UserRole(str, Enum):
    PM = "pm"
    ADMIN = "admin"
