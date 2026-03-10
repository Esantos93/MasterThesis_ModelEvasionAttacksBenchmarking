import ollama

def run_query(user_prompt):
    try:
        response = ollama.generate(
            model='gemma3:4b',
            prompt=user_prompt,
            stream=False  # To get the answer straight away
        )
        print(f"\n[Gemma 3]: {response['response']}")
    except Exception as e:
        print(f"Error connecting to Ollama: {e}")

if __name__ == "__main__":
    prompt = input("Enter your prompt: ")
    run_query(prompt)