import pandas as pd
import numpy as np
import json
from sklearn.utils import resample
import os

print("="*60)
print("🚀 CRÉATION DU BASELINE OPTIMAL AVEC LMD-2023")
print("="*60)

# ============================================================
# PARTIE 1 :  Charger vos logs (15,000)
# ============================================================
print("\n📂 [1/5] Chargement de vos logs...")

with open('baseline_sysmon.json', 'r', encoding='utf-8-sig') as f:
    your_data = json.load(f)

your_df = pd.DataFrame(your_data)
your_df['Source'] = 'your_lab'
print(f"   ✅ Vos logs:  {len(your_df)}")

# ============================================================
# PARTIE 2 :  Charger LMD-2023
# ============================================================
print("\n📂 [2/5] Chargement LMD-2023...")

# ⚠️ Ajustez le chemin selon votre emplacement
lmd_path = "LMD-2023 [1.75M Elements]Checked.csv"

lmd_df = pd.read_csv(lmd_path, low_memory=False)
print(f"   ✅ LMD-2023 total: {len(lmd_df)} logs")
print(f"   📋 Colonnes: {lmd_df.columns.tolist()[:15]}...")

# Vérifier la colonne Label
if 'Label' in lmd_df. columns:
    print(f"\n   📊 Distribution Label dans LMD:")
    print(lmd_df['Label'].value_counts())
elif 'ID' in lmd_df.columns:
    # Parfois le label est dans 'ID' ou dernière colonne
    print(f"   📊 Colonne 'ID':  {lmd_df['ID'].value_counts().head()}")

# ============================================================
# PARTIE 3 : Extraire UNIQUEMENT les logs NORMAUX de LMD
# ============================================================
print("\n📂 [3/5] Extraction des logs normaux de LMD...")

# La colonne Label:  0 = Normal, 1 = Attaque (ou inversement, vérifions)
# D'après la structure, Label semble être la dernière colonne
if 'Label' in lmd_df. columns:
    label_col = 'Label'
else:
    # Chercher la colonne label
    possible_labels = [col for col in lmd_df.columns if 'label' in col.lower()]
    if possible_labels:
        label_col = possible_labels[0]
    else:
        label_col = lmd_df.columns[-2]  # Avant-dernière colonne souvent

print(f"   🏷️ Colonne label utilisée: {label_col}")
print(f"   📊 Valeurs uniques: {lmd_df[label_col].unique()[:10]}")

# Identifier les logs normaux
# Dans LMD, généralement:  0 = Normal ou "Normal" ou "Benign"
lmd_df[label_col] = lmd_df[label_col].astype(str).str.lower().str.strip()

# Trouver les valeurs normales
normal_values = ['0', 'normal', 'benign', 'legitimate', '0.0']
lmd_normal = lmd_df[lmd_df[label_col]. isin(normal_values)].copy()

print(f"   ✅ Logs normaux LMD:  {len(lmd_normal)}")

# Si pas trouvé, prendre les plus fréquents (souvent les normaux)
if len(lmd_normal) == 0:
    print("   ⚠️ Aucun label 'normal' trouvé.  Analyse des valeurs...")
    print(lmd_df[label_col].value_counts().head(10))
    # Prendre la valeur la plus fréquente (généralement normale)
    most_common = lmd_df[label_col]. value_counts().index[0]
    lmd_normal = lmd_df[lmd_df[label_col] == most_common]. copy()
    print(f"   ✅ Utilisation de '{most_common}':  {len(lmd_normal)} logs")

# Limiter à 80,000 pour équilibrer avec vos données
if len(lmd_normal) > 80000:
    lmd_normal = lmd_normal.sample(n=80000, random_state=42)
    print(f"   📉 Limité à:  {len(lmd_normal)} logs")

lmd_normal['Source'] = 'lmd_2023_normal'

# ============================================================
# PARTIE 4 : Harmoniser les colonnes
# ============================================================
print("\n📂 [4/5] Harmonisation des colonnes...")

# Mapping des colonnes LMD vers vos colonnes
your_df_cols = your_df. columns.tolist()
print(f"   📋 Vos colonnes: {your_df_cols[: 10]}...")

# Colonnes importantes à garder
important_cols = [
    'EventID', 'TimeCreated', 'Computer', 'Image', 'CommandLine',
    'ParentImage', 'ParentCommandLine', 'User', 'ProcessId',
    'ParentProcessId', 'IntegrityLevel', 'TargetFilename',
    'DestinationIp', 'DestinationPort', 'SourceIp', 'SourcePort',
    'Source'
]

# Renommer les colonnes LMD si nécessaire
lmd_normal = lmd_normal. rename(columns={
    'UtcTime': 'TimeCreated',
    'SystemTime': 'TimeCreated'
})

# Filtrer EventIDs importants dans vos données
important_events = [1, 3, 5, 7, 8, 10, 11, 12, 13, 17, 18, 22, 23]
your_df_filtered = your_df[your_df['EventID'].isin(important_events)].copy()
print(f"   ✅ Vos logs filtrés: {len(your_df_filtered)}")

# Filtrer LMD aussi
if 'EventID' in lmd_normal.columns:
    lmd_normal['EventID'] = pd.to_numeric(lmd_normal['EventID'], errors='coerce')
    lmd_normal = lmd_normal[lmd_normal['EventID'].isin(important_events)]
    print(f"   ✅ LMD filtré par EventID: {len(lmd_normal)}")

# ============================================================
# PARTIE 5 : Data Augmentation de vos logs
# ============================================================
print("\n📂 [5/5] Data Augmentation + Fusion...")

# Augmenter vos logs x2
augmented = resample(
    your_df_filtered,
    replace=True,
    n_samples=len(your_df_filtered) * 2,
    random_state=42
)
augmented['Source'] = 'augmented'
print(f"   ✅ Logs augmentés: {len(augmented)}")

# Trouver colonnes communes
all_dfs = [your_df_filtered, augmented, lmd_normal]
common_cols = set(all_dfs[0].columns)
for df in all_dfs[1:]:
    common_cols = common_cols.intersection(set(df.columns))
common_cols = list(common_cols)

# S'assurer que les colonnes essentielles sont présentes
essential = ['EventID', 'Source']
for col in essential:
    if col not in common_cols and col in your_df_filtered.columns:
        common_cols.append(col)

print(f"   📋 Colonnes communes: {common_cols}")

# Supprimer les colonnes dupliquées dans chaque DataFrame avant fusion
cleaned_dfs = []
for df in all_dfs:
    # Sélectionner les colonnes communes présentes dans ce DataFrame
    selected_cols = [c for c in common_cols if c in df.columns]
    df_subset = df[selected_cols]
    # Supprimer les colonnes dupliquées (garder la première occurrence)
    df_subset = df_subset.loc[:, ~df_subset.columns.duplicated()]
    cleaned_dfs.append(df_subset)

# Fusionner
baseline_final = pd.concat(cleaned_dfs, ignore_index=True)

# Nettoyer
baseline_final = baseline_final.drop_duplicates()
baseline_final = baseline_final.sample(frac=1, random_state=42).reset_index(drop=True)
baseline_final['Label'] = 0  # Tout est Normal

# ============================================================
# RÉSULTATS
# ============================================================
print("\n" + "="*60)
print("📊 STATISTIQUES FINALES - BASELINE")
print("="*60)

print(f"\n🟢 Total logs baseline: {len(baseline_final)}")
print(f"\n📈 Distribution par source:")
print(baseline_final['Source']. value_counts())

if 'EventID' in baseline_final.columns:
    print(f"\n📈 Distribution EventID:")
    print(baseline_final['EventID'].value_counts().head(10))

baseline_final. to_csv('baseline_ready.csv', index=False)
print(f"\n✅ Fichier sauvegardé:  baseline_ready.csv")
print("="*60)

# ============================================================
# BONUS:  Extraire aussi les ATTAQUES de LMD pour attacks_ready. csv
# ============================================================
print("\n" + "="*60)
print("🔴 EXTRACTION DES ATTAQUES LMD")
print("="*60)

# Recharger LMD complet
lmd_df = pd.read_csv(lmd_path, low_memory=False)
lmd_df[label_col] = lmd_df[label_col].astype(str).str.lower().str.strip()

# Extraire les attaques (tout ce qui n'est pas normal)
attack_values = ['1', 'attack', 'malicious', '1.0']
lmd_attacks = lmd_df[~lmd_df[label_col].isin(normal_values)].copy()

print(f"🔴 Logs d'attaque LMD: {len(lmd_attacks)}")

if len(lmd_attacks) > 0:
    # Limiter pour équilibrer
    if len(lmd_attacks) > 50000:
        lmd_attacks = lmd_attacks.sample(n=50000, random_state=42)

    lmd_attacks['Label'] = 1
    lmd_attacks['Source'] = 'lmd_2023_attack'

    # Sauvegarder
    lmd_attacks.to_csv('attacks_lmd. csv', index=False)
    print(f"✅ Fichier sauvegardé:  attacks_lmd. csv ({len(lmd_attacks)} logs)")