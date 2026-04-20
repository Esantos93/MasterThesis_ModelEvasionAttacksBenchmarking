import time
from llama_cpp import Llama

def llm_call(ruta, nombre, template_tipo):
    print(f"\n--- TEST: {nombre} ---")
    llm = Llama(model_path=ruta, n_gpu_layers=-1, n_ctx=2048, add_bos=False, verbose=False)
    
    # Definimos el mensaje
    system_msg = "Eres un analista de seguridad de RISE."
    user_msg = "Genera un JSON simple de un paquete TCP."

    # Aplicamos el formato según el modelo
    if template_tipo == "llama":
        prompt = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{system_msg}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{user_msg}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
    else: # gemma
        prompt = f"<bos><|turn>system\n{system_msg}<turn|>\n<|turn>user\n{user_msg}<turn|>\n<|turn>model\n"

    start = time.time()
    res = llm(prompt, max_tokens=1000, temperature=0.0, top_p = 0.95)
    print(f"Respuesta ({time.time()-start:.2f}s):\n{res['choices'][0]['text']}")
    del llm

# Ejecutar cuando terminen las descargas
llm_call("./Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf", "Llama 3.1", "llama")
llm_call("./google_gemma-4-E4B-it-Q4_K_M.gguf", "Gemma 4", "gemma")