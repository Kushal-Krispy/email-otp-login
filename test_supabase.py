import os
from supabase import create_client

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not url or not key:
    print("Supabase environment variables are missing.")
    raise SystemExit

supabase = create_client(url, key)

response = supabase.table("users").select("id").limit(1).execute()

print("SUCCESS! Supabase connection is working.")
print("Database response:", response.data)