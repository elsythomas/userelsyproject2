# from rest_framework import permissions

# class IsAuthenticatedAndInAdminOrTeacherGroup(permissions.BasePermission):
#     """
#     Allows access only to authenticated users who are in the ADMIN or TEACHER role.
#     """

#     def has_permission(self, request, view):
#         if not request.user.is_authenticated:
#             return False
#         # Check if the user is an ADMIN (Role_id = 1) or a TEACHER (Role_id = 2)
#         if request.user.Role_id in [1, 2]:
#             return True
#         return False
# from rest_framework import permissions
# from myapp.models import User
# class IsAdminOrTeacher(permissions.BasePermission):
#     """
#     Allows access only to authenticated users with the ADMIN or TEACHER role.
#     """

#     def has_permission(self, request, view):
#         return request.user.is_authenticated and request.user.role in [Role.ADMIN, Role.TEACHER]

# # from rest_framework import permissions

# class IsAdminUser(permissions.BasePermission):
#     """
#     Allows access only to authenticated users with the ADMIN role.
#     """

#     def has_permission(self, request, view):
#         return request.user.is_authenticated and request.user.Role_id == 1

# from rest_framework import permissions
# from myapp.models import Role

# class IsAdminOrTeacher(permissions.BasePermission):
#     """
#     Allows access only to authenticated users with the ADMIN or TEACHER role.
#     """

#     def has_permission(self, request, view):
#         print(request.user.id)
#         return (
#             request.user.is_authenticated
#             and hasattr(request.user, "role")
#             and request.user.role  # Ensure role is assigned
#             and request.user.role.name in ["Admin","Teacher"]
#         )
# from rest_framework import Basepermissions
# from myapp.models import Role

# class IsAdminOrTeacher(permissions.BasePermission):
#     """
#     Allows access only to authenticated users with the ADMIN or TEACHER role.
#     """

#     def has_permission(self, request, view):
#         # print(f"User ID: {request.user.id}, Role: {getattr(request.user.role_id, 'name', None)}")  # Debugging

#         return (
#             request.user.is_authenticated
#             and request.user.role is not None  # ✅ Ensure user has a role assigned
#             and request.user.role.name in ["Admin", "Teacher"]  # ✅ Check role name
#         )
# class IsAdminOrTeacher(permissions.BasePermission):
#     """
#     Allows access only to authenticated users who are in the ADMIN .
#     """
#     def has_permission(self, request, view):
#         # print("rrr",request.user.Role)
#         if not request.user.is_authenticated:
#             return False
#         # Check if the user is in the ADMIN 
#         if request.user.role_id == 1:
#             return True
from rest_framework.permissions import BasePermission

class IsAdminOrTeacher(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        print(f"🔍 Checking permissions for user: {user}")
        
        # ✅ Ensure user is authenticated and role exists
        if not user or not hasattr(user, 'role') or user.role is None:
            print("❌ User is not authenticated")
            return False  # Reject request if role is missing
        if not hasattr(user, 'role') or user.role is None:
            print("❌ User has no role assigned")
            return False  

        print(f"✅ User role: {user.role.name}")  # Debugging output

        return user.role.name.lower() in ['admin', 'teacher']  # Ensure lowercase match
        
        # return user.role.name in ['admin', 'teacher']
    
# from rest_framework import BasePermission
# from rest_framework.permissions import BasePermission


# class IsAdminOrTeacher(BasePermission):
#     """
#     Custom permission to allow only users with 'admin' or 'teacher' roles to access the view.
#     """

#     def has_permission(self, request, view):
#         # Extract the role from the user object, assuming `Role` is related to the user.
#         user = request.user
#         # if not user or not user.is_authenticated:
#         if not user or not hasattr(user, 'role') or not user.role:
#             return False  # Deny if user is not authenticated

#         # Check if the user has 'admin' or 'teacher' role
#         return user.role.name in ['admin', 'teacher']
   
   
class IsAdmin(BasePermission):
    """
    Custom permission to check if the user is an admin.
    """

    def has_permission(self, request, view):
        
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return False  # User must be authenticated

        # Check if the user is an admin
        return  request.user.Role.id == 1

     

# class IsAdminUser(permissions.BasePermission):
#     """
#     Allows access only to authenticated users with the ADMIN role.
#     """

#     def has_permission(self, request, view):
#         return (
#             request.user.is_authenticated
#             and request.user.role  # Ensure role is assigned
#             and request.user.role.id == 1
#         )






































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




