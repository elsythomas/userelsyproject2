# USER_STATUS = (
#     ('deleted', 'Deleted'),
#     ('active', 'Active'),
#     ('in_active', 'InActive'),
#     ('pending', 'Pending')
# )


# USER_TYPE = (
#     ('admin', 'Admin User'),
#     ('teacher', 'Department teacher'),
#     ('student', 'student'),
# )

# ### ORGANIZATION ROLE ###
# ROLE_STATUS = (
#     ('deleted', 'Deleted'),
#     ('active', 'Active'),
#     ('in_active', 'InActive')
# )

# ROLE_STATUS_DETAILS = {
#     'deleted': 'Deleted',
#     'active': 'Active',
#     'in_active': 'InActive'
# }

# ROLE_TYPE = (
#     ('admin', 'Admin Role'),
#     ('teacher', 'Teacher Role'),
#     ('student', ' Student Role'),
# )

# ROLE_TYPE_DETAILS = {
#     'admin': 'Admin Role',
#     'teacher': 'Teacher Role',
#     'student': 'Student Role',
# }
# myapp/utils.py

STATUS_PENDING = 'pending'
STATUS_ACTIVE = 'active'

STATUS_CHOICES = [
    (STATUS_PENDING, 'Pending'),
    (STATUS_ACTIVE, 'Active'),
]
