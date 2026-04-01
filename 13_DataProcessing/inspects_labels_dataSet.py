import pandas as pd

# Definimos el nombre del archivo
file_path = '/home/santos/Desktop/Traffic_Files/Edge-IIoTset_dataset/Attack_traffic/DDoS_ICMP_Flood_attack.csv'

# Leemos SOLO la primera fila para no saturar la RAM
df_columns = pd.read_csv(file_path, nrows=0)

print(f"Number of labels found: {len(df_columns.columns)}")
print("-" * 30)

# Listar todas las etiquetas
for i, col in enumerate(df_columns.columns):
    print(f"{i+1}. {col}")

# Si quieres ver un ejemplo de los datos de la primera fila para entender el formato:
# sample = pd.read_csv(file_path, nrows=1)
# print("\nEjemplo de la primera fila:")
# print(sample.iloc[0])