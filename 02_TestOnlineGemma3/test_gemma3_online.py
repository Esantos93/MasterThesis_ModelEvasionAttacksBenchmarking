import os
from google import genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# SETTINGS
API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY)

def run_query_api(user_prompt):
    try:
        # We call Gemma 3 (version 4b)
        response = client.models.generate_content(
            model='gemma-3-4b-it', 
            contents=user_prompt
        )
        print(f"\n[Gemma 3 Cloud API]: {response.text}")
        
    except Exception as e:
        print(f"Error connecting to the Google API: {e}")

if __name__ == "__main__":
    # Sample prompt focused on your thesis
    print("--- Payload generator for test bench (KTH/RISE thesis) ---")
    prompt = input("Enter the instruction: ")
    run_query_api(prompt)