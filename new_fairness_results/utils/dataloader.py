import glob
import pandas as pd
import os
import re

import utils.preprocessing as preprocessing

DATA_CONFIGS = {
    'stresstest': {
        'data_patterns': [
            "<system>_unbalanced_<timestamp>.csv",
        ]
    },
    'baseline': {
        'data_patterns': [
            "<system>_baseline_<timestamp>.csv",
        ],
    },
}

def load_experiment_data(src_dir="./", systems_to_load=None):
    """Load data and preprocess as experiment data from the specified source directory, organizing it by solution and system.
       By default load all systems (control-plane, network, ...). You may pass the exact list here.
    """
    experiments = {}
    
    latest_stress_files = _get_latest_file_paths_generic(src_dir, DATA_CONFIGS['stresstest'])
    latest_baseline_files = _get_latest_file_paths_generic(src_dir, DATA_CONFIGS['baseline'])
    
    #zip the stress test and baseline files based on solution and system
    for (solution, system, timestamp), stress_file in latest_stress_files.items():
        if systems_to_load and system not in systems_to_load:
            continue

        baseline_file = latest_baseline_files.get((solution, system, timestamp))
        if baseline_file:
            baseline_experiment = preprocessing.TestResultDeserializer().load_experiment(baseline_file)
            baseline_metadata = baseline_experiment.as_baseline_metadata() if baseline_experiment else {}
            stress_experiment = preprocessing.TestResultDeserializer().load_experiment(stress_file, baseline_metadata)
            experiments[solution] = experiments.get(solution, {})
            experiments[solution][system] = experiments[solution].get(system, {})
            experiments[solution][system]['baseline'] = baseline_experiment
            experiments[solution][system]['stress_test'] = stress_experiment
            experiments[solution][system]['baseline_metadata'] = baseline_metadata
            experiments[solution][system]['timestamp'] = timestamp
        else:
            print(f"No matching baseline file for {stress_file}")
    
    return experiments
    
    

def get_latest_stresstest_file_paths(src_dir="./"):
    """Get the file paths of the most recent stresstest data files"""
    return _get_latest_file_paths_generic(src_dir, DATA_CONFIGS['stresstest'])

def get_latest_baseline_file_paths(src_dir="./"):
    """Get the file paths of the most recent baseline data files"""
    return _get_latest_file_paths_generic(src_dir, DATA_CONFIGS['baseline'])

def load_latest_stresstest_data(src_dir="./"):
    """Load the most recent test data"""
    return _load_data_generic(src_dir,  DATA_CONFIGS['stresstest'])

def load_latest_baseline_data(src_dir="./"):
    """Load baseline test data"""
    return _load_data_generic(src_dir,  DATA_CONFIGS['baseline'])

def _get_latest_file_paths_generic(src_dir, config):
    """Get the file paths of the most recent data files based on the provided configuration
    Expect the data to be in such path format: <src_dir>/<solution>/<data_pattern>
    The data pattern should include a placeholder for the system and timestamp, which will be used to identify the latest file for each system.
    """
    # The system dinamically extract the system name and timestamp according to the data pattern
    # Do not always assume the same file name format or the separator, but extract it from the data pattern
    file_paths = {}
    for data_pattern in config['data_patterns']:
        # Construct glob pattern: replace placeholders with *
        glob_pattern = data_pattern.replace("<system>", "*").replace("<timestamp>", "*")
        # Search in src_dir/<solution>/<glob_pattern>
        search_path = os.path.join(src_dir, "*", glob_pattern)
        files = glob.glob(search_path)

        # Construct regex pattern for extraction
        # Escape the pattern, then replace escaped placeholders with regex groups
        regex_pattern = re.escape(data_pattern) \
            .replace(re.escape("<system>"), r"(?P<system>.+)") \
            .replace(re.escape("<timestamp>"), r"(?P<timestamp>\d+)")
        # Map to store the latest file for each (solution, system) pair
        # Key: (solution, system), Value: (timestamp, filepath)
        latest_files = {}

        for filepath in files:
            filename = os.path.basename(filepath)
            solution = os.path.basename(os.path.dirname(filepath))
            
            match = re.match(regex_pattern, filename)
            if match:
                system = match.group("system")
                timestamp = int(match.group("timestamp"))

                key = (solution, system)
                if key not in latest_files or timestamp > latest_files[key][0]:
                    latest_files[key] = (timestamp, filepath)
        # Add the latest files to the result
        for (solution, system), (timestamp, filepath) in latest_files.items():
            file_paths[(solution, system, timestamp)] = filepath

    return file_paths



def _load_data_generic(src_dir, config):
    """Load data based on the provided configuration
    Expect the data to be in such path format: <src_dir>/<solution>/<data_pattern>
    Label the experiment type also based on the system (e.g., control_plane, network, etc.).
    The data pattern should include a placeholder for the system and timestamp, which will be used to identify the latest file for each system.
    """

    data_frames = []
    # Reuse the logic to get the latest files
    latest_files = _get_latest_file_paths_generic(src_dir, config)

    if latest_files:
        # Load the identified latest files
        for (solution, system, timestamp), filepath in latest_files.items():
            try:
                df = pd.read_csv(filepath)
                # Add metadata columns
                df['solution'] = solution
                df['system'] = system
                df['experiment_timestamp'] = timestamp
                data_frames.append(df)
            except Exception as e:
                print(f"Error loading {filepath}: {e}")

    if not data_frames:
        return pd.DataFrame()

    return pd.concat(data_frames, ignore_index=True)


# Test the data loader
# if __name__ == "__main__":
#     src_dir = "./new_fairness_results/raw"
#     experiments = load_experiment_data(src_dir)
#     print(f"Loaded experiments: {list(experiments.keys())}")
#     print(f"Systems for capsule: {list(experiments['capsule'].keys())}")
#     print(experiments["capsule"]["control_plane"]["baseline"].summary_stats)
#     print(experiments["capsule"]["control_plane"]["stress_test"].summary_stats)
#     print(experiments["capsule"]["control_plane"]["baseline_metadata"])