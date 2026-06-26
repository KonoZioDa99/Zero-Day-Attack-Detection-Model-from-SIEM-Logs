import pandas as pd
import numpy as np
import json
import os
import zipfile
from sklearn.utils import resample
from glob import glob

print("="*70)
print("🚀 CRÉATION DU DATASET OPTIMAL POUR DÉTECTION ZERO-DAY (V2)")
print("="*70)

# ============================================================
# CONFIGURATION - AJUSTEZ CES CHEMINS
# ============================================================
YOUR_BASELINE_PATH = "baseline_sysmon.json"
LMD_PATH = "LMD-2023 [1.75M Elements]Checked.csv"
EVTX_CSV_PATH = "evtx_data.csv"  # ← Fichier CSV de EVTX-ATTACK-SAMPLES
OTRF_PATH = "windows"  # Dossier OTRF extrait

# Objectifs
TARGET_NORMAL = 100000
TARGET_ATTACKS = 25000

# ============================================================
# PARTIE 1 :  VOS LOGS NORMAUX + AUGMENTATION
# ============================================================
print("\n" + "="*70)
print("📂 [1/5] VOS LOGS NORMAUX")
print("="*70)

with open(YOUR_BASELINE_PATH, 'r', encoding='utf-8-sig') as f:
    your_data = json.load(f)

your_df = pd.DataFrame(your_data)
your_df['Source'] = 'your_lab'
your_df['Label'] = 0
print(f"   ✅ Vos logs:  {len(your_df)}")

# Augmentation x3
your_augmented = resample(your_df, replace=True, n_samples=len(your_df) * 3, random_state=42)
your_augmented['Source'] = 'your_lab_augmented'
your_augmented['Label'] = 0
print(f"   ✅ Après augmentation x3: {len(your_augmented)}")

# ============================================================
# PARTIE 2 :  LMD-2023 (NORMAL + ATTAQUES)
# ============================================================
print("\n" + "="*70)
print("📂 [2/5] LMD-2023")
print("="*70)

lmd_df = pd.read_csv(LMD_PATH, low_memory=False)
print(f"   ✅ LMD-2023 total: {len(lmd_df)}")

# Identifier le label
label_col = 'Label' if 'Label' in lmd_df.columns else 'ID'
lmd_df['_label_str'] = lmd_df[label_col].astype(str).str.lower().str.strip()

# Séparer Normal et Attaques
normal_values = ['0', 'normal', 'benign', '0. 0', 'legitimate']
lmd_normal = lmd_df[lmd_df['_label_str'].isin(normal_values)].copy()
lmd_attacks = lmd_df[~lmd_df['_label_str']. isin(normal_values)].copy()

print(f"   🟢 LMD Normal: {len(lmd_normal)}")
print(f"   🔴 LMD Attaques: {len(lmd_attacks)}")

# Échantillonner
if len(lmd_normal) > 80000:
    lmd_normal = lmd_normal.sample(n=80000, random_state=42)
if len(lmd_attacks) > 8000:
    lmd_attacks = lmd_attacks.sample(n=8000, random_state=42)

lmd_normal['Source'] = 'lmd_normal'
lmd_normal['Label'] = 0
lmd_attacks['Source'] = 'lmd_attack'
lmd_attacks['Label'] = 1

print(f"   🟢 LMD Normal (échantillon): {len(lmd_normal)}")
print(f"   🔴 LMD Attaques (échantillon): {len(lmd_attacks)}")

# ============================================================
# PARTIE 3 : EVTX-ATTACK-SAMPLES (evtx_data. csv)
# ============================================================
print("\n" + "="*70)
print("📂 [3/5] EVTX-ATTACK-SAMPLES")
print("="*70)

evtx_df = pd.DataFrame()

if os.path.exists(EVTX_CSV_PATH):
    evtx_df = pd.read_csv(EVTX_CSV_PATH, low_memory=False)
    print(f"   ✅ EVTX-ATTACK-SAMPLES chargé: {len(evtx_df)} logs")
    print(f"   📋 Colonnes: {evtx_df.columns.tolist()[:10]}...")

    # Renommer les colonnes si nécessaire
    evtx_df = evtx_df.rename(columns={
        'event_id': 'EventID',
        'EventId': 'EventID',
        'event. code': 'EventID',
        'winlog.event_id': 'EventID'
    })

    # Afficher les catégories d'attaques si disponibles
    attack_cols = [col for col in evtx_df. columns if 'attack' in col.lower() or 'technique' in col.lower() or 'tactic' in col. lower()]
    if attack_cols:
        print(f"   📊 Colonnes d'attaques trouvées: {attack_cols}")
        for col in attack_cols[: 2]:
            print(f"   📈 {col}: {evtx_df[col].value_counts().head(5).to_dict()}")

    # Limiter à 10,000
    if len(evtx_df) > 10000:
        evtx_df = evtx_df.sample(n=10000, random_state=42)

    evtx_df['Source'] = 'evtx_attack_samples'
    evtx_df['Label'] = 1
    print(f"   ✅ EVTX échantillon final: {len(evtx_df)}")
else:
    print(f"   ⚠️ Fichier non trouvé: {EVTX_CSV_PATH}")
    print("   💡 Téléchargez evtx_data. csv depuis https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES")

# ============================================================
# PARTIE 4 : OTRF SECURITY-DATASETS (ZIPs → JSON)
# ============================================================
print("\n" + "="*70)
print("📂 [4/5] OTRF SECURITY-DATASETS")
print("="*70)

otrf_events = []

if os.path.exists(OTRF_PATH):
    # Trouver tous les fichiers ZIP
    zip_files = glob(f"{OTRF_PATH}/**/*.zip", recursive=True)
    print(f"   📁 Fichiers ZIP trouvés: {len(zip_files)}")

    # Parser un échantillon de ZIPs (max 50 pour la vitesse)
    for zip_path in zip_files[: 50]:
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                for file_name in z.namelist():
                    if file_name.endswith('.json'):
                        with z.open(file_name) as f:
                            content = f.read().decode('utf-8')
                            # Les fichiers peuvent contenir plusieurs lignes JSON
                            for line in content.strip().split('\n'):
                                if line.strip():
                                    try:
                                        event = json.loads(line)
                                        if isinstance(event, dict):
                                            # Extraire la catégorie d'attaque du chemin
                                            parts = zip_path.replace("\\", "/").split("/")
                                            category = parts[-2] if len(parts) > 1 else "unknown"
                                            event['AttackCategory'] = category
                                            event['SourceFile'] = os.path.basename(zip_path)
                                            otrf_events.append(event)
                                    except json.JSONDecodeError:
                                        continue
        except Exception as e:
            continue

    if otrf_events:
        otrf_df = pd.DataFrame(otrf_events)

        # Standardiser EventID
        if 'EventID' not in otrf_df.columns:
            for col in ['event_id', 'EventId', 'event.code']:
                if col in otrf_df. columns:
                    otrf_df['EventID'] = otrf_df[col]
                    break

        # Limiter à 7,000
        if len(otrf_df) > 7000:
            otrf_df = otrf_df.sample(n=7000, random_state=42)

        otrf_df['Source'] = 'otrf_security_datasets'
        otrf_df['Label'] = 1

        print(f"   ✅ OTRF logs parsés: {len(otrf_df)}")

        if 'AttackCategory' in otrf_df.columns:
            print(f"   📊 Catégories d'attaques OTRF:")
            print(otrf_df['AttackCategory'].value_counts().head(8))
    else:
        otrf_df = pd.DataFrame()
        print("   ⚠️ Aucun log OTRF parsé")
else:
    otrf_df = pd.DataFrame()
    print(f"   ⚠️ Dossier OTRF non trouvé:  {OTRF_PATH}")
    print("   💡 Téléchargez depuis https://github.com/OTRF/Security-Datasets")

# ============================================================
# PARTIE 5 : FUSION FINALE ET RATIO 90/10
# ============================================================
print("\n" + "="*70)
print("📂 [5/5] FUSION FINALE (RATIO 90% Baseline / 10% Attaque)")
print("="*70)

# 1. Préparation des listes (Comme votre code original)
normal_dfs = [your_df, your_augmented, lmd_normal]
attack_dfs = [lmd_attacks]

if 'evtx_df' in locals() and len(evtx_df) > 0:
    attack_dfs.append(evtx_df)
if 'otrf_df' in locals() and len(otrf_df) > 0:
    attack_dfs.append(otrf_df)

# 2. Nettoyage pour éviter l'erreur "FutureWarning" (concaténation vide)
# On garde seulement les DataFrames qui ne sont pas vides
normal_dfs = [df for df in normal_dfs if not df.empty]
attack_dfs = [df for df in attack_dfs if not df.empty]

# 3. Fusionner (Concat)
if normal_dfs:
    all_normal = pd.concat(normal_dfs, ignore_index=True)
else:
    all_normal = pd.DataFrame()

if attack_dfs:
    all_attacks = pd.concat(attack_dfs, ignore_index=True)
else:
    all_attacks = pd.DataFrame() # Crée un vide pour éviter le crash

print(f"   🟢 Total Normal disponible: {len(all_normal):,}")
print(f"   🔴 Total Attaques disponible: {len(all_attacks):,}")

# --------------------------------------------------------
# 4. ÉQUILIBRAGE (C'est ici que la magie 90/10 opère)
# --------------------------------------------------------

# A. On limite d'abord les normaux à la cible (ex: 100 000)
# (Assurez-vous que TARGET_NORMAL est défini plus haut, sinon mettez 100000 ici)
target_normal_limit = 100000
if len(all_normal) > target_normal_limit:
    all_normal = all_normal.sample(n=target_normal_limit, random_state=42)

# B. CALCUL DYNAMIQUE DU 10%
# Si Normal = 90%, alors Attaque = Normal / 9
if len(all_normal) > 0:
    target_attacks_calculated = int(len(all_normal) / 9)
else:
    target_attacks_calculated = 0

print(f"   🎯 Objectif calculé : {len(all_normal):,} Normaux vs {target_attacks_calculated:,} Attaques")

# C. On limite les attaques au nombre calculé
if len(all_attacks) > target_attacks_calculated:
    all_attacks = all_attacks.sample(n=target_attacks_calculated, random_state=42)
    print(f"   ✂️ Attaques réduites à {len(all_attacks):,} (Ratio respecté)")
else:
    print(f"   ⚠️ Pas assez d'attaques pour atteindre 10%. On garde tout ({len(all_attacks):,})")

# --------------------------------------------------------
# 5. FINALISATION (Comme votre code original)
# --------------------------------------------------------

# Colonnes communes
if len(all_normal) > 0 and len(all_attacks) > 0:
    common_cols = list(set(all_normal.columns).intersection(set(all_attacks.columns)))
else:
    common_cols = all_normal.columns.tolist() if len(all_normal) > 0 else []

# Ajouter colonnes essentielles si manquantes
for col in ['EventID', 'Label', 'Source']:
    if col not in common_cols:
        common_cols.append(col)
        # Initialiser la colonne pour éviter erreur lors du concat
        if col not in all_normal.columns and len(all_normal) > 0: all_normal[col] = 0
        if col not in all_attacks.columns and len(all_attacks) > 0: all_attacks[col] = 1

# Nettoyer les colonnes pour être sûr qu'elles existent
common_cols = [c for c in common_cols if c in all_normal.columns or c in all_attacks.columns]

print(f"   📋 Colonnes communes: {len(common_cols)}")

# Fusion finale
final_dataset = pd.concat([
    all_normal[common_cols] if not all_normal.empty else pd.DataFrame(),
    all_attacks[common_cols] if not all_attacks.empty else pd.DataFrame()
], ignore_index=True)

# Mélanger
final_dataset = final_dataset.sample(frac=1, random_state=42).reset_index(drop=True)

# ============================================================
# STATISTIQUES FINALES
# ============================================================
print("\n" + "="*70)
print("📊 STATISTIQUES FINALES - DATASET ZERO-DAY")
print("="*70)

print(f"\n📦 TOTAL: {len(final_dataset)} logs")

if len(final_dataset) > 0:
    label_dist = final_dataset['Label'].value_counts()
    total = len(final_dataset)
    print(f"\n📈 Distribution des Labels:")
    # Utilisation de .get() pour éviter erreur si un label manque
    n_norm = label_dist.get(0, 0)
    n_att = label_dist.get(1, 0)
    print(f"   🟢 Normal (0): {n_norm:,} ({n_norm/total*100:.1f}%)")
    print(f"   🔴 Attaque (1): {n_att:,} ({n_att/total*100:.1f}%)")

    print(f"\n📈 Distribution par Source:")
    print(final_dataset['Source'].value_counts())

    # Sauvegarder (J'ai corrigé les espaces dans les noms de fichiers)
    final_dataset.to_csv('zeroday_dataset.csv', index=False)
    print(f"\n✅ Fichier principal sauvegardé: zeroday_dataset.csv")

# Sauvegarde des fichiers bruts séparés
all_normal.to_csv('baseline_optimal.csv', index=False)
all_attacks.to_csv('attacks_optimal.csv', index=False)

print(f"✅ Fichiers auxiliaires sauvegardés (baseline_optimal.csv, attacks_optimal.csv)")

print("\n" + "="*70)
print("🎉 DATASET ZERO-DAY CRÉÉ AVEC SUCCÈS!")
print("="*70)