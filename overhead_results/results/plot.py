import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def remove_outliers_iqr(df, group_cols, value_col):
    def filter_group(group):
        q1 = group[value_col].quantile(0.25)
        q3 = group[value_col].quantile(0.75)
        iqr = q3 - q1
        lower = q1 - 1.5 * iqr
        upper = q3 + 1.5 * iqr
        return group[(group[value_col] >= lower) & (group[value_col] <= upper)]

    return (
        df
        .groupby(group_cols, group_keys=False)
        .apply(filter_group)
    )


# --- CONFIGURATION ---
# Define your file pairs here. 
# Each entry represents a solution with its name and corresponding files.
SOLUTIONS = [
    {
        'name': 'Capsule',            # Label for the legend
        'tests_file': 'overhead_capsule.csv',     # Test definition file for this solution
        'data_file': 'CPU_API_server.csv'# Measurement data file for this solution
    },
    {
        'name': 'reference',
        'tests_file': 'overhead_reference.csv',
        'data_file': 'CPU_API_server.csv'
    },
    {
        'name': 'vcluster',
        'tests_file': 'overhead_vcluster.csv',
        'data_file': 'CPU_API_server.csv'
    },
    {
        'name': 'kubevirt',
        'tests_file': 'overhead_kubevirt.csv',
        'data_file': 'CPU_API_server.csv'
    }
    # Add more dictionaries here for Solution C, D, etc.
]

OFFSET_MINUTES = 58*60 + 30           # Custom offset (Data time = Test time + Offset)

# Column mapping
TEST_START_COL = 'Start'
TEST_END_COL = 'End'
TEST_ID_COL = 'Num_Tenants'      # X-axis grouping
DATA_TIMESTAMP_COL = 'Time'
DATA_VALUE_COL = '192.168.17.82:6443'         # Y-axis value
# ---------------------

plot_data = []
offset = pd.Timedelta(seconds=OFFSET_MINUTES)

for sol in SOLUTIONS:
    print(f"Processing {sol['name']}...")
    
    # 1. Load Tests
    try:
        tests = pd.read_csv(sol['tests_file'])
        # Parse timestamps (using your specific format)
        tests[TEST_START_COL] = pd.to_datetime(tests[TEST_START_COL], format='%Y%m%d_%H%M%S')
        tests[TEST_END_COL] = pd.to_datetime(tests[TEST_END_COL], format='%Y%m%d_%H%M%S')
    except Exception as e:
        print(f"Error loading test file {sol['tests_file']}: {e}")
        continue

    # 2. Load Data
    try:
        data = pd.read_csv(sol['data_file'])
        data[DATA_TIMESTAMP_COL] = pd.to_datetime(data[DATA_TIMESTAMP_COL])
    except Exception as e:
        print(f"Error loading data file {sol['data_file']}: {e}")
        continue

    # 3. Extract Windows
    for _, row in tests.iterrows():
        # Calculate window with offset
        window_start = row[TEST_START_COL] + offset
        window_end = row[TEST_END_COL] + offset
        
        # Filter data
        mask = (data[DATA_TIMESTAMP_COL] >= window_start) & (data[DATA_TIMESTAMP_COL] <= window_end)
        subset = data.loc[mask, [DATA_VALUE_COL]].copy()
        
        # Add metadata columns
        subset[TEST_ID_COL] = row[TEST_ID_COL]
        subset['Solution'] = sol['name']  # This column maps to the color (hue)
        
        plot_data.append(subset)

# Combine everything
if plot_data:
    combined_df = pd.concat(plot_data, ignore_index=True)

    # # Remove outliers per Solution and Num_Tenants
    # combined_df = remove_outliers_iqr(
    #     combined_df,
    #     group_cols=['Solution', TEST_ID_COL],
    #     value_col=DATA_VALUE_COL
    # )

    # 4. Plot
    plt.figure(figsize=(14, 7))
    
    # The 'hue' parameter assigns colors based on the 'Solution' column
    sns.boxplot(data=combined_df, x=TEST_ID_COL, y=DATA_VALUE_COL, hue='Solution', showfliers=False)
    
    #plt.title(f'Comparison of Solutions per {TEST_ID_COL} (Offset: {OFFSET_MINUTES} min)')
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.legend(title='Solution Name')
    plt.ylabel('API server CPU Usage (# of cores)')
    
    plt.tight_layout()
    plt.savefig('solutions_comparison.png')
    plt.show()
    print("Plot saved as 'solutions_comparison.png'.")
else:
    print("No data found to plot.")