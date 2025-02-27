
from myapp.utils import ROLE_TYPE
from rest_framework.permissions import BasePermission

class IsAdminOrTeacher(BasePermission):
    def has_permission(self, request, view):
        # print("hyyy")
        user = request.user
        print(f"🔍 Checking permissions for user1: {user}")
        
        # ✅ Ensure user is authenticated and role exists
        if not user or not hasattr(user, 'role') or user.role is None == ROLE_TYPE[2][1]:
            print("❌ User is not authenticated") 
            return False  # Reject request if role is missing
        if not hasattr(user, 'role') or user.role is None == ROLE_TYPE[2][1]:
            print("❌ User has no role assigned")
            return False  

        print(f"✅ User role: {user.role.name}")  # Debugging output
        # print(user.role.name.lower(),'ggggggggggggggg')

        return user.role.name.lower() in [ROLE_TYPE[0][0], ROLE_TYPE[1][0]]  # Ensure lowercase match
        
        # return user.role.name in ['admin', 'teacher']
   
   
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

     








































# # from .models import User, Admin


# class IsAuthenticatedAndInAdminGroup(permissions.BasePermission):
#     """
#     Allows access only to authenticated users who are in the ADMIN .
#     """
#     def has_permission(self, request, view):
#         # print("rrr",request.user.Role)
#         if not request.user.is_authenticated:
#             return False
#         # Check if the user is in the ADMIN 
#         if request.user.Role_id == 1:
#             return True
        
# from rest_framework.permissions import BasePermission

# class IsAdminOrTeacher(BasePermission):
#     """
#     Custom permission to allow only users with 'admin' or 'teacher' roles to access the view.
#     """

#     def has_permission(self, request, view):
#         # Extract the role from the user object, assuming `Role` is related to the user.
#         user = request.user
#         if not user or not user.is_authenticated:
#             return False  # Deny if user is not authenticated

#         # Check if the user has 'admin' or 'teacher' role
#         return user.Role.name in ['admin', 'teacher']
       
# class IsAdmin(BasePermission):
#     """
#     Custom permission to check if the user is an admin.
#     """

#     def has_permission(self, request, view):
        
#         # Check if the user is authenticated
#         if not request.user.is_authenticated:
#             return False  # User must be authenticated

#         # Check if the user is an admin
#         return  request.user.Role.id == 1
    
    
    
# class IsAdminUser(permissions.BasePermission):
#     def has_permission(self, request, view):
#         return request.user.is_authenticated and request.user.is_staff




