

ROLE_TYPE = (
    ('admin', 'Admin Role'),
    ('teacher', 'Teacher Role'),
    ('student', ' Student Role'),
)



STATUS_PENDING = 'pending'
STATUS_ACTIVE = 'active'

STATUS_CHOICES = [
    (STATUS_PENDING, 'Pending'),
    (STATUS_ACTIVE, 'Active'),
]

USER_STATUS =(
    ('active', 'Active'),
    ('pending', 'Pending'),
    
)




import gspread
from oauth2client.service_account import ServiceAccountCredentials

# Path to the service account JSON key file
GOOGLE_CREDENTIALS_FILE = r"C:\\Users\\Elsy Thomas\\main-mechanism-452807-b9-1de978714f60.json"

# Google Sheet ID (Get it from the URL of your sheet)
GOOGLE_SHEET_ID = "1YNZQTs9mnUQ4TRE26DKIkT6EWJaiY5ib-qagg5RSOgI"

# Authenticate and connect to Google Sheets
def get_google_sheet():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDENTIALS_FILE, scope)
    client = gspread.authorize(creds)

    # Open the sheet by ID
    sheet = client.open_by_key(GOOGLE_SHEET_ID).sheet1  # Modify if using multiple sheets
    return sheet

def update_google_sheet(user):
    """
    Updates Google Sheets with a new user entry.
    """
    try:
        sheet = get_google_sheet()

        # Append the new user row
        new_row = [user.id, user.name, user.email, user.role.name if user.role else "No Role", "Pending"]
        sheet.append_row(new_row)

        print("✅ Google Sheet updated successfully!")
    except Exception as e:
        print(f"❌ Error updating Google Sheets: {e}")


import gspread
from oauth2client.service_account import ServiceAccountCredentials

# Path to your Google Service Account JSON key file
GOOGLE_CREDENTIALS_FILE = r"C:\\Users\\Elsy Thomas\\main-mechanism-452807-b9-1de978714f60.json"

# Google Sheet ID
GOOGLE_SHEET_ID = "1YNZQTs9mnUQ4TRE26DKIkT6EWJaiY5ib-qagg5RSOgI"

# Authenticate and connect to Google Sheets
def get_google_sheet():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDENTIALS_FILE, scope)
    client = gspread.authorize(creds)
    sheet = client.open_by_key(GOOGLE_SHEET_ID).sheet1  # Modify if using multiple sheets
    return sheet

def update_user_status_in_google_sheet(email, new_status):
    """
    Updates the user's status in Google Sheets.
    """
    try:
        sheet = get_google_sheet()
        data = sheet.get_all_records()  # Get all records as a list of dictionaries

        for i, row in enumerate(data, start=2):  # Start from row 2 (after headers)
            if row["Email"] == email:
                sheet.update_cell(i, 5, new_status)  # Assuming "Status" is in column 5
                print(f"✅ Updated {email}'s status to {new_status} in Google Sheets.")
                return

        print(f"⚠️ Email {email} not found in Google Sheets.")
    except Exception as e:
        print(f"❌ Error updating Google Sheets: {e}")
