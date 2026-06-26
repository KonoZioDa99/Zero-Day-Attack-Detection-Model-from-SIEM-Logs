import pandas as pd
import json

# Charger le JSON
with open('baseline_sysmon.json', 'r', encoding='utf-8') as f:
    data = json. load(f)

# Convertir en DataFrame
df = pd.DataFrame(data)

print(f"✅ Logs chargés:  {len(df)}")
print(f"📊 Colonnes disponibles: {df.columns.tolist()}")
print(f"\n📈 Distribution EventID:")
print(df['EventID'].value_counts().head(10))

# Garder les EventIDs Sysmon importants pour la détection
# 1=ProcessCreate, 3=NetworkConnect, 7=ImageLoad, 10=ProcessAccess
# 11=FileCreate, 12/13=Registry, 22=DNSQuery
important_events = [1, 3, 7, 8, 10, 11, 12, 13, 22, 23]
df_filtered = df[df['EventID'].isin(important_events)].copy()

# Supprimer colonnes vides
df_filtered = df_filtered. dropna(axis=1, how='all')

# Supprimer doublons
df_filtered = df_filtered.drop_duplicates()

# Ajouter label
df_filtered['Label'] = 0  # 0 = Normal

# Sauvegarder
df_filtered.to_csv('baseline_ready.csv', index=False)
print(f"\n✅ Logs après nettoyage:  {len(df_filtered)}")
print(f"📁 Fichier sauvegardé:  baseline_ready.csv")