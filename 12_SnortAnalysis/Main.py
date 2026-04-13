import Run_Snort
import Process_Logs

def main():
    print("-" * 40)
    print(" SNORT 3 ANALYSIS SYSTEM ")
    print("-" * 40)

    # STEP 1: Run Snort and capture the returned arguments
    # The Run_Snort script handles interaction and execution
    config_used = Run_Snort.execute_snort()

    # STEP 2: Process the results
    # We pass the captured arguments to the processor
    if config_used:
            Process_Logs.rename_json(
                pcap=config_used["pcap"],
                ruleset=config_used["ruleset"],
                builtin=config_used["builtin"]
            )
            print("\n[Main] All tasks completed successfully.")
    else:
            print("\n[Main] Snort execution failed. Skipping log processing.")

if __name__ == "__main__":
    main()