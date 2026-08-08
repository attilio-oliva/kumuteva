import glob
import json
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
    
    

def load_manifest(csv_path):
    """Load the run manifest sitting beside a result CSV, if there is one.

    Runs produced before manifests existed have none; callers must treat the
    result as optional rather than assuming it is present.
    """
    directory = os.path.dirname(csv_path)
    filename = os.path.basename(csv_path)
    match = re.match(r"(?P<system>.+)_(?:baseline|unbalanced)_(?P<timestamp>\d+)\.csv", filename)
    if not match:
        return None

    manifest_path = os.path.join(
        directory,
        f"{match.group('system')}_manifest_{match.group('timestamp')}.json",
    )
    if not os.path.exists(manifest_path):
        return None

    try:
        with open(manifest_path) as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read manifest {manifest_path}: {error}")
        return None


def load_all_experiment_runs(src_dir="./", systems_to_load=None):
    """Load *every* run, not just the most recent one per (solution, system).

    `load_experiment_data` keeps only the newest timestamp, which is right for
    rendering a single figure but discards exactly the repetitions needed to put
    confidence intervals on a degradation factor. This returns

        runs[solution][system] -> [ {baseline, stress_test, timestamp, manifest}, ... ]

    ordered by timestamp, so repeated runs can be aggregated with
    `utils.stats.aggregate_runs`.
    """
    stress_files = _get_all_file_paths_generic(src_dir, DATA_CONFIGS["stresstest"])
    baseline_files = _get_all_file_paths_generic(src_dir, DATA_CONFIGS["baseline"])

    runs = {}
    for (solution, system, timestamp), stress_file in sorted(stress_files.items()):
        if systems_to_load and system not in systems_to_load:
            continue

        baseline_file = baseline_files.get((solution, system, timestamp))
        if not baseline_file:
            print(f"No matching baseline file for {stress_file}")
            continue

        baseline_experiment = preprocessing.TestResultDeserializer().load_experiment(baseline_file)
        if baseline_experiment is None:
            continue
        baseline_metadata = baseline_experiment.as_baseline_metadata()
        stress_experiment = preprocessing.TestResultDeserializer().load_experiment(
            stress_file, baseline_metadata
        )

        runs.setdefault(solution, {}).setdefault(system, []).append(
            {
                "baseline": baseline_experiment,
                "stress_test": stress_experiment,
                "baseline_metadata": baseline_metadata,
                "timestamp": timestamp,
                "manifest": load_manifest(stress_file),
            }
        )

    return runs


def _get_all_file_paths_generic(src_dir, config):
    """Like `_get_latest_file_paths_generic`, but keeps every timestamp."""
    file_paths = {}
    for data_pattern in config["data_patterns"]:
        glob_pattern = data_pattern.replace("<system>", "*").replace("<timestamp>", "*")
        search_path = os.path.join(src_dir, "*", glob_pattern)

        regex_pattern = (
            re.escape(data_pattern)
            .replace(re.escape("<system>"), r"(?P<system>.+)")
            .replace(re.escape("<timestamp>"), r"(?P<timestamp>\d+)")
        )

        for filepath in glob.glob(search_path):
            filename = os.path.basename(filepath)
            solution = os.path.basename(os.path.dirname(filepath))
            match = re.match(regex_pattern, filename)
            if match:
                key = (solution, match.group("system"), int(match.group("timestamp")))
                file_paths[key] = filepath

    return file_paths


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