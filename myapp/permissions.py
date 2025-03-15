
from myapp.utils import ROLE_TYPE
from rest_framework.permissions import BasePermission

class IsAdminOrTeacher(BasePermission):
    def has_permission(self, request, view):
        
        user = request.user
        print(f"🔍 Checking permissions for user1: {user}")
        
        #  Ensure user is authenticated and role exists
        if not user or not hasattr(user, 'role') or user.role is None == ROLE_TYPE[2][1]:
            print(" User is not authenticated") 
            return False  # Reject request if role is missing
        if not hasattr(user, 'role') or user.role is None == ROLE_TYPE[2][1]:
            print(" User has no role assigned")
            return False  

        print(f"✅ User role: {user.role.name}")  # Debugging output
        

        return user.role.name.lower() in [ROLE_TYPE[0][0], ROLE_TYPE[1][0]]  
        
        
   
   
class IsAdmin(BasePermission):
    """
    Custom permission to check if the user is an admin.
    """

    def has_permission(self, request, view):
        # print()
        
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return False  # User must be authenticated

        # Check if the user is an admin
        return  request.user.role.id == ROLE_TYPE[0][1]