import pandas as pd
import numpy as np
import glob

class ExperimentData:
    """
    Container for experiment data with methods to compute common metrics for plotting.
    """
    def __init__(self, df, metadata=None):
        self.raw_df = df
        self.metadata = metadata or {}
        self.t1_df = self._preprocess(df[df['role'] == 'tenant1'].copy())
        self.t2_df = self._preprocess(df[df['role'] == 'tenant2'].copy())
        # Precompute summary stats for quick access
        self.t1_summary, self.t2_summary = self.get_summary_stats()
        
    def _preprocess(self, df):
        # Ensure numeric types for critical columns
        if 'start_time' in df.columns:
            df['start_time'] = pd.to_numeric(df['start_time'], errors='coerce')
            # Calculate elapsed time relative to the start of this dataset
            min_time = df['start_time'].min()
            df['elapsed_seconds'] = df['start_time'] - min_time
        
        if 'duration_ms' in df.columns:
            df['duration_ms'] = pd.to_numeric(df['duration_ms'], errors='coerce')
            df['duration_seconds'] = df['duration_ms'] / 1000.0
            
        # Calculate relative metrics if baseline is available in metadata
        if 'baseline_metrics' in self.metadata:
            baseline = self.metadata['baseline_metrics'].get('tenant1_avg_latency_ms')
            if baseline and 'duration_ms' in df.columns:
                df['relative_increase_percent'] = ((df['duration_ms'] - baseline) / baseline) * 100
                df['relative_multiplier'] = df['duration_ms'] / baseline
        
        # Sort for time-series analysis
        sort_cols = []
        if 'role' in df.columns:
            sort_cols.append('role')
        if 'elapsed_seconds' in df.columns:
            sort_cols.append('elapsed_seconds')
            
        if sort_cols:
            df = df.sort_values(sort_cols).reset_index(drop=True)
        
        return df
    
    def get_time_series(self, window_size=1.0, group_by='role', window_step=None):
        """Compute time-series metrics for both tenants."""
        self.t1_time_series = self.get_time_series_single_tenant(self.t1_df, window_size, group_by, window_step)
        self.t2_time_series = self.get_time_series_single_tenant(self.t2_df, window_size, group_by, window_step)
        return self.t1_time_series, self.t2_time_series
    
    def get_time_series_single_tenant(self, df, window_size=1.0, group_by='role', window_step=None):
        """
        Compute metrics aggregated by time window.
        Returns DataFrame with lists of: window_start, throughput, avg_latency, p95_latency, error_rate
        """
        if 'elapsed_seconds' not in df.columns or df.empty:
            return pd.DataFrame()
            
        if window_step is None:
            window_step = window_size

        # Use efficient groupby for non-overlapping windows (step == size)
        if abs(window_step - window_size) < 1e-9:
            df = df.copy()
            df['window_idx'] = (df['elapsed_seconds'] // window_size).astype(int)
            df['window_start'] = df['window_idx'] * window_size
            
            agg_funcs = {
                'duration_ms': ['count', 'mean', lambda x: np.percentile(x, 95), 'sum'],
                'is_error': ['sum']
            }
            
            columns = ['window_start']
            if group_by and group_by in df.columns:
                time_series = df.groupby(['window_start', group_by]).agg(agg_funcs).reset_index()
                columns.append(group_by)
            else:
                time_series = df.groupby('window_start').agg(agg_funcs).reset_index()
                
            columns.extend(['count', 'avg_latency_ms', 'p95_latency_ms', 'total_duration_ms', 'error_count'])
            time_series.columns = columns
            time_series['throughput'] = time_series['count'] / window_size
            time_series['error_rate'] = time_series['error_count'] / time_series['count'] if time_series['count'].sum() > 0 else 0.0
            
            return time_series
        
        # Sliding window implementation
        max_time = df['elapsed_seconds'].max()
        window_starts = np.arange(0, max_time + window_step, window_step)
        
        rows = []
        times = df['elapsed_seconds'].values
        has_group = group_by and group_by in df.columns
        
        for start in window_starts:
            end = start + window_size
            idx_start = np.searchsorted(times, start, side='left')
            idx_end = np.searchsorted(times, end, side='left')
            
            if idx_start == idx_end:
                continue
                
            window_slice = df.iloc[idx_start:idx_end]
            
            if has_group:
                for name, group in window_slice.groupby(group_by):
                    rows.append({
                        'window_start': start,
                        group_by: name,
                        'count': len(group),
                        'avg_latency_ms': group['duration_ms'].mean(),
                        'p95_latency_ms': np.percentile(group['duration_ms'], 95),
                        'total_duration_ms': group['duration_ms'].sum(),
                        'error_count': group['is_error'].sum()
                    })
            else:
                rows.append({
                    'window_start': start,
                    'count': len(window_slice),
                    'avg_latency_ms': window_slice['duration_ms'].mean(),
                    'p95_latency_ms': np.percentile(window_slice['duration_ms'], 95),
                    'total_duration_ms': window_slice['duration_ms'].sum(),
                    'error_count': window_slice['is_error'].sum()
                })
        
        if not rows:
            return pd.DataFrame()
            
        time_series = pd.DataFrame(rows)
        time_series['throughput'] = time_series['count'] / window_size
        time_series['error_rate'] = time_series['error_count'] / time_series['count']
        
        return time_series
    

    def get_summary_stats(self, group_by='role'):
        """Compute overall summary statistics."""
        def p50(x): return np.percentile(x, 50)
        def p95(x): return np.percentile(x, 95)
        def p99(x): return np.percentile(x, 99)
        
        agg_funcs = {
            'duration_ms': ['count', 'mean', 'std', 'min', p50, p95, p99, 'max'],
            'is_error': ['mean', 'sum']
        }
        
        def compute_stats(df):
            if group_by and group_by in df.columns:
                return df.groupby(group_by).agg(agg_funcs)
            else:
                return df.agg(agg_funcs)
            
        t1_stats = compute_stats(self.t1_df)
        t2_stats = compute_stats(self.t2_df)
        
        return (t1_stats, t2_stats)
        
    def as_baseline_metadata(self):
        """Extract baseline metrics as metadata for quick comparison."""
        if 'duration_ms' in self.t1_df.columns:
            tenant1_avg_latency = self.t1_df['duration_ms'].mean()
            tenant1_stdev_latency = self.t1_df['duration_ms'].std()
            return {
                'tenant1_avg_latency_ms': tenant1_avg_latency,
                'tenant1_stdev_latency_ms': tenant1_stdev_latency,
            }
        return {}
    
    def __repr__(self):
        return f"ExperimentData(metadata={self.metadata}, t1_summary={self.t1_summary}, t2_summary={self.t2_summary})"
    
    def to_summary_string(self) -> str:
                return f"Tenant1: {self.t1_summary['duration_ms']['mean'].iloc[0]:.2f} ± {self.t1_summary['duration_ms']['std'].iloc[0]:.2f} ms (p95: {self.t1_summary['duration_ms']['p95'].iloc[0]:.2f} ms) (range: {self.t1_summary['duration_ms']['min'].iloc[0]:.2f}-{self.t1_summary['duration_ms']['max'].iloc[0]:.2f} ms) [data points: {self.t1_summary['duration_ms']['count'].iloc[0]}]\n       " + \
               f"Tenant2: {self.t2_summary['duration_ms']['mean'].iloc[0]:.2f} ± {self.t2_summary['duration_ms']['std'].iloc[0]:.2f} ms (p95: {self.t2_summary['duration_ms']['p95'].iloc[0]:.2f} ms) (range: {self.t2_summary['duration_ms']['min'].iloc[0]:.2f}-{self.t2_summary['duration_ms']['max'].iloc[0]:.2f} ms) [data points: {self.t2_summary['duration_ms']['count'].iloc[0]}]"
    
    
class TestResultDeserializer:
    """
    Deserializer for fairness test results.
    Capable of loading data from multiple CSV files and associated metadata.
    """
    def __init__(self, column_mapping=None):
        # Default mapping for standard fields. 
        # Update this if the new CSV format uses different column names.
        self.column_mapping = column_mapping or {
            'timestamp_secs': 'start_time',
            'latency_ms': 'duration_ms',
            'tenant': 'role',
            'is_error': 'is_error',
            'label': 'operation',
        }

    def load_experiment(self, data_files, metadata={}) -> ExperimentData:
        """
        Load an experiment from a list of CSV files and an optional metadata file.
        
        Args:
            data_files: List of file paths or glob patterns for CSV data.
            metadata: Dictionary containing metadata for the experiment (optional).
        """
        dfs = []
        # Expand globs if necessary
        all_files = []
        if isinstance(data_files, str):
            all_files = glob.glob(data_files)
        else:
            for f in data_files:
                all_files.extend(glob.glob(f))
                
        for file_path in all_files:
            try:
                df = pd.read_csv(file_path)
                dfs.append(df)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        
        if not dfs:
            print("No data files found.")
            return None
            
        full_df = pd.concat(dfs, ignore_index=True)
        
        # Apply column mapping if columns exist
        if self.column_mapping:
            rename_map = {k: v for k, v in self.column_mapping.items() 
                         if k in full_df.columns and k != v}
            if rename_map:
                full_df.rename(columns=rename_map, inplace=True)
        
        return ExperimentData(full_df, metadata)
