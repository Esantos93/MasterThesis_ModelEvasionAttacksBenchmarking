import pandas as pd

# We set the path to the CSV file containing the traffic data for attacks from the Edge-IIoTset dataset.
file_path = '/home/santos/Desktop/Traffic_Files/Edge-IIoTset_dataset/Attack_traffic/DDoS_ICMP_Flood_attack.csv'

# We reed the first row of the CSV file to get the column names, which represent the labels in the dataset.
df_columns = pd.read_csv(file_path, nrows=0)

print(f"Number of labels found: {len(df_columns.columns)}")
print("-" * 30)

# We list the column names to understand the different labels present in the dataset.
for i, col in enumerate(df_columns.columns):
    print(f"{i+1}. {col}")