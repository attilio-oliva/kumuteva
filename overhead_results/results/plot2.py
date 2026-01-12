import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# 1. SETUP: Configuration Definition
# ==========================================

# Define your solutions.
# Note that we now include 'schedule_file' for each entry.
CONFIGURATIONS = [
    {
        'name': 'reference',
        'schedule_file': 'overhead_reference.csv', # <--- Unique schedule for A
        'file_total': 'CPU_cluster.csv',
        'file_contrib': 'CPU_API_server.csv',
        'offset': -60*62 ,
        'color_contrib': "#0060E7",  # Dark Blue
        'color_rest': "#5F93DC"      # Light Blue
    },
    {
        'name': 'capsule',
        'schedule_file': 'overhead_capsule.csv', # <--- Unique schedule for A
        'file_total': 'CPU_cluster.csv',
        'file_contrib': 'CPU_API_server.csv',
        'offset': -60*62 ,
        'color_contrib': "#E00000",  # Dark Blue
        'color_rest': "#DB7777"      # Light Blue
    },
    {
        'name': 'vcluster',
        'schedule_file': 'overhead_vcluster.csv', # <--- Unique schedule for A
        'file_total': 'CPU_cluster.csv',
        'file_contrib': 'CPU_API_server.csv',
        'offset': -60*62 ,
        'color_contrib': "#00E038",  # Dark Blue
        'color_rest': "#7ED694"      # Light Blue
    },
    {
        'name': 'kubevirt',
        'schedule_file': 'overhead_kubevirt.csv', # <--- Unique schedule for A
        'file_total': 'CPU_cluster.csv',
        'file_contrib': 'CPU_API_server.csv',
        'offset': -60*62 ,
        'color_contrib': "#C4CB00",  # Dark Blue
        'color_rest': "#D7DA78"      # Light Blue
    }
]

start_first_load = "Fri Jan  9 17:29:46 CET 2026"

# ==========================================
# 3. PROCESSING LOGIC
# ==========================================

all_results = []

for config in CONFIGURATIONS:
    print(f"Processing {config['name']}...")
    
    # 1. Load the SPECIFIC schedule for this config
    try:
        df_sched = pd.read_csv(config['schedule_file'])
        df_t = pd.read_csv(config['file_total'])
        df_c = pd.read_csv(config['file_contrib'])
    except FileNotFoundError as e:
        print(f"  Error: {e}. Skipping.")
        continue
    
    # 2. Parse Dates (Schedule)
    df_sched['Start'] = pd.to_datetime(df_sched['Start'], format='%Y%m%d_%H%M%S')
    df_sched['End'] = pd.to_datetime(df_sched['End'], format='%Y%m%d_%H%M%S')
    
    # 3. Parse Dates (Data) & Apply Offset
    # Note: Ensure your CSV timestamps are parsable. Add format=... if needed.
    df_t['Time'] = pd.to_datetime(df_t['Time']) + pd.Timedelta(seconds=config['offset'])
    df_c['Time'] = pd.to_datetime(df_c['Time']) + pd.Timedelta(seconds=config['offset'])

    # Sort for speed
    df_t = df_t.sort_values('Time')
    df_c = df_c.sort_values('Time')
    
    # 4. Iterate over THIS specific schedule
    config_results = []
    for idx, row in df_sched.iterrows():
        t_start = row['Start']
        t_end = row['End']
        
        # Filter Data
        subset_t = df_t[(df_t['Time'] >= t_start) & (df_t['Time'] <= t_end)]
        subset_c = df_c[(df_c['Time'] >= t_start) & (df_c['Time'] <= t_end)]
        
        # Calculate
        val_total = subset_t['1m load average'].mean() if not subset_t.empty else 0
        val_contrib = subset_c['192.168.17.82:6443'].mean() if not subset_c.empty else 0
        
        config_results.append({
            'Num_Tenants': row['Num_Tenants'], # This ID links the tests across files
            'Total_Mean': val_total,
            'Contrib_Mean': val_contrib,
            'Config': config['name']
        })
    
    all_results.extend(config_results)

df_all = pd.DataFrame(all_results)

# ==========================================
# 4. VISUALIZATION (Stacked + Grouped)
# ==========================================
plt.style.use('seaborn-v0_8-whitegrid')

# Master list of all Test IDs found in ANY schedule
if not df_all.empty:
    test_ids = sorted(df_all['Num_Tenants'].unique())
    n_configs = len(CONFIGURATIONS)
    indices = np.arange(len(test_ids))

    # Layout dimensions
    group_width = 0.8
    bar_width = group_width / n_configs

    fig, ax = plt.subplots(figsize=(15, 8))

    for i, config in enumerate(CONFIGURATIONS):
        cfg_name = config['name']
        
        # Filter data for this config
        cfg_data = df_all[df_all['Config'] == cfg_name]
        
        # Align data to the Master Test ID list
        # This handles cases where one schedule might be missing a test ID
        cfg_data = cfg_data.set_index('Num_Tenants').reindex(test_ids).reset_index()
        
        # X positions
        x_pos = indices + (i * bar_width) - (group_width / 2) + (bar_width / 2)
        
        # Values (fill NaN with 0 for missing tests)
        val_cont = cfg_data['Contrib_Mean'].fillna(0)
        val_tot = cfg_data['Total_Mean'].fillna(0)
        
        # Calc Stack Segments
        # Clip ensures we don't get weird negative bars if data has errors
        val_rest = (val_tot - val_cont).clip(lower=0) 
        
        # Colors
        c_contrib = config.get('color_contrib', 'black')
        c_rest = config.get('color_rest', 'gray')
        
        # Plot
        ax.bar(x_pos, val_cont, width=bar_width * 0.9, 
               color=c_contrib, label=f"{cfg_name} (Contrib)")
        
        ax.bar(x_pos, val_rest, bottom=val_cont, width=bar_width * 0.9, 
               color=c_rest, label=f"{cfg_name} (Rest)")

    ax.set_xlabel('Num_Tenants (Test ID)', fontsize=12)
    ax.set_ylabel('Mean Value', fontsize=12)
    ax.set_title('Comparison: Stacked Bars (Independent Schedules)', fontsize=14)
    ax.set_xticks(indices)
    ax.set_xticklabels(test_ids)
    
    # Optional: Clean up legend to show only 2 items per config if desired, 
    # currently it shows all 4 parts.
    ax.legend()
    
    plt.tight_layout()
    #plt.show()
    plt.savefig('multi_schedule_plot.png')
else:
    print("No results found. Please check your input files and dates.")