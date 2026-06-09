import time
from llama_cpp import Llama, ChatCompletionRequestMessage

def llm_call(path, name):
    print(f"\n--- TEST: {name} ---")
    llm = Llama(model_path=path, n_gpu_layers=-1, n_ctx=2048, add_bos=False, verbose=False)
    
    # We define the content of the prompt as a list of messages with roles
    messages: list[ChatCompletionRequestMessage] = [
        {"role": "system", "content": "You are a security analyst at RISE."},
        {"role": "user", "content": "Generate a simple JSON of a TCP packet."}
    ]
    
    start = time.time() # We measure the time taken for the response
    res = llm.create_chat_completion(
            messages=messages,
            max_tokens=1000,
            temperature=0.0,
            top_p=0.95,
            stream=False
        )

    duration = time.time() - start

    # We check if the response is a dictionary, which is the expected format for the output
    assert isinstance(res, dict)
    # The answer lies in a different path within the resulting JSON
    text_response = res["choices"][0]["message"]["content"]
    
    print(f"The generation of the answer took ({duration:.2f}s):\n{text_response}")
    del llm

# Function calls for testing the models
llm_call("./Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf", "Llama 3.1")
llm_call("./google_gemma-4-E4B-it-Q4_K_M.gguf", "Gemma 4")