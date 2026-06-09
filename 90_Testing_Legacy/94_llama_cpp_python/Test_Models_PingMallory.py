import time, os, re, math
from llama_cpp import Llama, ChatCompletionRequestMessage

def get_dynamic_n_ctx(json_path, max_tokens_response):
    # 1. We count the number of characters in the input JSON file to estimate the required n_ctx (window size) for the LLM.
    char_count = os.path.getsize(json_path)
    
    # 2. Estimate 1 token ≈ 3 characters (this is a common approximation, but it can vary).
    # We add
    estimated_tokens = (char_count // 3) + max_tokens_response
    
    # 3. We adjust n_ctx based on the estimated tokens, ensuring it is a power of 2 and does not exceed a reasonable limit for our hardware.
    # If 
    if estimated_tokens <= 2048:
        return 2048
    
    # We calculate the next power of 2 greater than or equal to the estimated tokens to ensure efficient memory usage and performance.
    power = math.ceil(math.log2(estimated_tokens))
    dynamic_ctx = int(2**power)
    
    # Safe upper limit for n_ctx is set to 32k for 8B quantized models, as going beyond this may lead to performance issues or memory constraints.
    # 32k is a common upper limit for n_ctx in many LLMs, especially when using quantized models, to ensure that the model can handle the context without running into memory issues.
    return min(dynamic_ctx, 32768)





def llm_call(model_location, model_name, input_json_path, max_tokens_response=3000):
    print(f"\n--- TESTING TRAFFIC MODIFICATION WITH MODEL: {model_name} ---")
    
    # We read the JSON file containing the original traffic data to be modified
    with open(input_json_path, 'r') as f:
        original_json_data = f.read()

    # We estimate the required n_ctx (Window size) based on the input JSON size and the expected response size.
        needed_ctx = get_dynamic_n_ctx(input_json_path, max_tokens_response)
        print(f"Adjusting n_ctx to: {needed_ctx}")

    llm = Llama(model_path=model_location, n_gpu_layers=-1, n_ctx=needed_ctx, add_bos=False, verbose=False)
    
    # We define the content of the prompt as a list of messages with roles
    messages: list[ChatCompletionRequestMessage] = [
        {
            "role": "user", 
            "content": (
            f"Read the following network traffic JSON: {original_json_data}. "
            "Perform the following two modifications: "
            "1. Change the 'dst_port' of all packets to 4444. "
            "2. Prepend the hex value '78' to the beginning of the 'payload_hex' field. "
            "Output the result strictly as a JSON object, maintaining the original structure."
        )
        }
    ]
    
    start = time.time() # We measure the time taken for the response
    res = llm.create_chat_completion(
            messages=messages,
            max_tokens=max_tokens_response,
            temperature=0.0,
            top_p=0.95,
            stream=False,
            response_format={ "type": "json_object" }
        )

    duration = time.time() - start

    # We check if the response is a dictionary, which is the expected format for the output
    assert isinstance(res, dict)
    # The answer lies in a different path within the resulting JSON
    text_response = res["choices"][0]["message"]["content"]
    
    # We save the modified JSON to a new file for further analysis.
    base_name = os.path.splitext(input_json_path)[0]
    output_path = f"{base_name}_{model_name}_modified.json"

    try:
        with open(output_path, 'w') as f:
            f.write(text_response)
        # The script shows how much time the modification took and where the modified JSON is saved for further analysis.
        print(f"Success! The generation of the answer took ({duration:.2f}s): Modified JSON saved to {output_path}")
    except Exception as e:
        print(f"Error saving modified JSON: {e}")
    
    
    del llm

# Function calls for testing the models
llm_call("./Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf", "Llama 3.1", "../01_Files/test_ping_Mallory.json")
llm_call("./google_gemma-4-E4B-it-Q4_K_M.gguf", "Gemma 4", "../01_Files/test_ping_Mallory.json")