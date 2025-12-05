import pandas as pd
import numpy as np
import re
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

class SSHThreatParser:
    def __init__(self):
        self.connection_tracking = defaultdict(list)
        self.session_metrics = defaultdict(dict)

    def safe_extract_number(self, text, pattern, default=0):
        """Safely extract numbers from text using regex."""
        try:
            match = re.search(pattern, str(text))
            return int(match.group(1)) if match else default
        except (ValueError, AttributeError):
            return default

    def safe_extract_string(self, text, pattern, default=''):
        """Safely extract strings from text using regex."""
        try:
            match = re.search(pattern, str(text))
            return match.group(1) if match else default
        except AttributeError:
            return default

    def parse_tcp_features(self, info_str):
        """Enhanced TCP feature extraction with error handling."""
        features = {}

        # Port extraction with validation
        port_match = re.search(r'(\d+)\s*>\s*(\d+)', str(info_str))
        if port_match:
            features['source_port'] = int(port_match.group(1))
            features['dest_port'] = int(port_match.group(2))
            features['is_ssh_port'] = (int(port_match.group(2)) == 22)
        else:
            features['source_port'] = 0
            features['dest_port'] = 0
            features['is_ssh_port'] = False

        # TCP flags with comprehensive detection
        flag_patterns = {
            'syn': r'\bSYN\b',
            'ack': r'\bACK\b',
            'fin': r'\bFIN\b',
            'rst': r'\bRST\b',
            'psh': r'\bPSH\b',
            'urg': r'\bURG\b'
        }

        detected_flags = []
        for flag, pattern in flag_patterns.items():
            if re.search(pattern, str(info_str)):
                detected_flags.append(flag.upper())
                features[f'has_{flag}'] = 1
            else:
                features[f'has_{flag}'] = 0

        features['tcp_flags'] = ','.join(detected_flags) if detected_flags else 'NONE'
        features['flag_count'] = len(detected_flags)

        # Connection state determination
        if features['has_syn'] and not features['has_ack']:
            features['connection_state'] = 'SYN_SENT'
        elif features['has_syn'] and features['has_ack']:
            features['connection_state'] = 'SYN_ACK'
        elif features['has_ack'] and not any([features['has_syn'], features['has_fin'], features['has_rst']]):
            features['connection_state'] = 'ESTABLISHED'
        elif features['has_fin']:
            features['connection_state'] = 'FIN_WAIT'
        elif features['has_rst']:
            features['connection_state'] = 'RESET'
        else:
            features['connection_state'] = 'UNKNOWN'

        # Numeric features with safe extraction
        features['seq_num'] = self.safe_extract_number(info_str, r'Seq=(\d+)')
        features['ack_num'] = self.safe_extract_number(info_str, r'Ack=(\d+)')
        features['window_size'] = self.safe_extract_number(info_str, r'Win=(\d+)')
        features['tcp_length'] = self.safe_extract_number(info_str, r'Len=(\d+)')
        features['mss'] = self.safe_extract_number(info_str, r'MSS=(\d+)')
        features['ts_val'] = self.safe_extract_number(info_str, r'TSval=(\d+)')
        features['ts_ecr'] = self.safe_extract_number(info_str, r'TSecr=(\d+)')
        features['window_scale'] = self.safe_extract_number(info_str, r'WS=(\d+)')

        return features

    def parse_ssh_features(self, info_str):
        """Enhanced SSH feature extraction with threat detection focus."""
        features = {}

        # SSH message type classification
        if 'Protocol' in info_str:
            features['ssh_msg_type'] = 'PROTOCOL'
            features['ssh_version'] = self.safe_extract_string(info_str, r'(SSH-[\d\.]+)')

            # SSH implementation detection
            if 'OpenSSH' in info_str:
                features['ssh_implementation'] = self.safe_extract_string(info_str, r'(OpenSSH_[\d\.p\d]+)')
            else:
                features['ssh_implementation'] = 'UNKNOWN'

            # Client/Server role
            if 'Client:' in info_str:
                features['ssh_role'] = 'CLIENT'
            elif 'Server:' in info_str:
                features['ssh_role'] = 'SERVER'
            else:
                features['ssh_role'] = 'UNKNOWN'

        elif 'Key Exchange' in info_str:
            features['ssh_msg_type'] = 'KEY_EXCHANGE'
            if 'Init' in info_str:
                features['ssh_kex_stage'] = 'INIT'
            else:
                features['ssh_kex_stage'] = 'OTHER'

        elif 'Diffie-Hellman' in info_str:
            features['ssh_msg_type'] = 'DIFFIE_HELLMAN'
            if 'Group Exchange Request' in info_str:
                features['ssh_dh_stage'] = 'GROUP_EXCHANGE_REQUEST'
            elif 'Group Exchange Group' in info_str:
                features['ssh_dh_stage'] = 'GROUP_EXCHANGE_GROUP'
            elif 'Group Exchange Init' in info_str:
                features['ssh_dh_stage'] = 'GROUP_EXCHANGE_INIT'
            elif 'Group Exchange Reply' in info_str:
                features['ssh_dh_stage'] = 'GROUP_EXCHANGE_REPLY'
            else:
                features['ssh_dh_stage'] = 'OTHER'

        elif 'New Keys' in info_str:
            features['ssh_msg_type'] = 'NEW_KEYS'

        elif 'Encrypted packet' in info_str:
            features['ssh_msg_type'] = 'ENCRYPTED'
            features['ssh_packet_length'] = self.safe_extract_number(info_str, r'len=(\d+)')

            # Determine role for encrypted packets
            if 'Client:' in info_str:
                features['ssh_role'] = 'CLIENT'
            elif 'Server:' in info_str:
                features['ssh_role'] = 'SERVER'
            else:
                features['ssh_role'] = 'UNKNOWN'
        else:
            features['ssh_msg_type'] = 'OTHER'

        # Set default values for missing features
        for key in ['ssh_role', 'ssh_kex_stage', 'ssh_dh_stage', 'ssh_packet_length']:
            if key not in features:
                features[key] = 'UNKNOWN' if 'stage' in key or 'role' in key else 0

        return features

    def calculate_threat_indicators(self, df):
        """Calculate threat detection indicators for SSH brute force."""
        threat_features = []

        # Track connections per source IP
        source_connections = df.groupby('source_ip').size().to_dict()

        # Track failed connections (RST packets)
        failed_connections = df[df['info'].str.contains('RST', na=False)].groupby('source_ip').size().to_dict()

        # Track connection attempts per port
        port_attempts = df.groupby(['source_ip', 'dest_port']).size().to_dict()

        # Track SSH-specific attempts
        ssh_attempts = df[(df['protocol'] == 'SSHv2') | (df['dest_port'] == 22)].groupby('source_ip').size().to_dict()

        # Calculate time-based metrics
        ip_time_stats = df.groupby('source_ip')['timestamp'].agg(['min', 'max', 'count']).to_dict('index')

        for idx, row in df.iterrows():
            threat_indicators = {}

            source_ip = row['source_ip']
            dest_port = row.get('dest_port', 0)
            timestamp = row['timestamp']

            # Connection frequency indicators
            threat_indicators['connections_from_source'] = source_connections.get(source_ip, 0)
            threat_indicators['failed_connections_from_source'] = failed_connections.get(source_ip, 0)
            threat_indicators['attempts_on_port'] = port_attempts.get((source_ip, dest_port), 0)
            threat_indicators['ssh_attempts_from_source'] = ssh_attempts.get(source_ip, 0)

            # Calculate failure rate
            if threat_indicators['connections_from_source'] > 0:
                threat_indicators['failure_rate'] = (
                        threat_indicators['failed_connections_from_source'] /
                        threat_indicators['connections_from_source']
                )
            else:
                threat_indicators['failure_rate'] = 0.0

            # Time-based indicators
            threat_indicators['time_seconds'] = float(timestamp)

            # Calculate session duration for this IP
            if source_ip in ip_time_stats:
                time_stats = ip_time_stats[source_ip]
                session_duration = time_stats['max'] - time_stats['min']
                threat_indicators['session_duration'] = session_duration

                # Connection rate (connections per second)
                if session_duration > 0:
                    threat_indicators['connection_rate'] = threat_indicators['connections_from_source'] / session_duration
                else:
                    threat_indicators['connection_rate'] = threat_indicators['connections_from_source']
            else:
                threat_indicators['session_duration'] = 0.0
                threat_indicators['connection_rate'] = 0.0

            # SSH-specific threat indicators
            if row['protocol'] == 'SSHv2':
                threat_indicators['is_ssh_traffic'] = 1
                threat_indicators['is_encrypted_ssh'] = 1 if 'Encrypted packet' in str(row['info']) else 0
                threat_indicators['is_key_exchange'] = 1 if 'Key Exchange' in str(row['info']) else 0
            else:
                threat_indicators['is_ssh_traffic'] = 0
                threat_indicators['is_encrypted_ssh'] = 0
                threat_indicators['is_key_exchange'] = 0

            # Enhanced brute force indicators with lower thresholds
            threat_indicators['is_brute_force_indicator'] = 1 if (
                    threat_indicators['connections_from_source'] > 2 and  # Lowered from 5
                    threat_indicators['failure_rate'] > 0.2 and  # Lowered from 0.5
                    dest_port == 22
            ) else 0

            # Fixed rapid connections logic
            threat_indicators['rapid_connections'] = 1 if (
                    threat_indicators['connection_rate'] > 1.0 and  # More than 1 connection per second
                    threat_indicators['connections_from_source'] > 3
            ) else 0

            # SSH-specific brute force patterns
            threat_indicators['ssh_brute_force_pattern'] = 1 if (
                    threat_indicators['ssh_attempts_from_source'] > 2 and
                    threat_indicators['connection_rate'] > 0.5
            ) else 0

            # High volume SSH activity
            threat_indicators['high_volume_ssh'] = 1 if (
                    threat_indicators['ssh_attempts_from_source'] >= 5
            ) else 0

            threat_features.append(threat_indicators)

        return pd.DataFrame(threat_features)

    def create_labels_improved(self, df):
        """Improved threat classification labels for brute force detection."""
        labels = []

        # Sort by timestamp to process chronologically
        df_sorted = df.sort_values('timestamp').reset_index(drop=True)

        # Track connection attempts per source IP over time
        source_stats = defaultdict(lambda: {
            'total_connections': 0,
            'failed_connections': 0,
            'ssh_attempts': 0,
            'first_seen': None,
            'last_seen': None,
            'connection_times': []
        })

        for idx, row in df_sorted.iterrows():
            source_ip = row['source_ip']
            timestamp = row['timestamp']

            # Update source statistics
            stats = source_stats[source_ip]
            stats['total_connections'] += 1
            stats['last_seen'] = timestamp
            if stats['first_seen'] is None:
                stats['first_seen'] = timestamp
            stats['connection_times'].append(timestamp)

            # Count failed connections (RST packets)
            if 'RST' in str(row['info']):
                stats['failed_connections'] += 1

            # Count SSH attempts
            if row['protocol'] == 'SSHv2' or row.get('dest_port') == 22:
                stats['ssh_attempts'] += 1

            # Calculate current metrics
            total_conns = stats['total_connections']
            failed_conns = stats['failed_connections']
            ssh_conns = stats['ssh_attempts']

            # Time-based analysis
            session_duration = stats['last_seen'] - stats['first_seen']

            # Connection rate (connections per second)
            if session_duration > 0:
                connection_rate = total_conns / session_duration
            else:
                connection_rate = total_conns  # All in same second

            # Failure rate
            failure_rate = failed_conns / total_conns if total_conns > 0 else 0

            # Recent connection burst (last 10 seconds)
            recent_threshold = timestamp - 10  # 10 seconds ago
            recent_connections = sum(1 for t in stats['connection_times'] if t >= recent_threshold)

            # IMPROVED BRUTE FORCE DETECTION
            is_malicious = False

            # Condition 1: High connection rate to SSH port
            if (ssh_conns >= 2 and connection_rate > 0.3):  # 2+ SSH attempts at >0.3/sec
                is_malicious = True

            # Condition 2: Multiple failed connections
            if (failed_conns >= 1 and total_conns >= 2):  # 1+ failures out of 2+ attempts
                is_malicious = True

            # Condition 3: Connection burst pattern
            if recent_connections >= 3:  # 3+ connections in last 10 seconds
                is_malicious = True

            # Condition 4: Sustained SSH activity
            if (ssh_conns >= 2 and session_duration >= 0):  # 2+ SSH over any duration
                is_malicious = True

            # Condition 5: High failure rate with SSH
            if (failure_rate > 0.2 and ssh_conns >= 1):  # 20%+ failure rate with SSH
                is_malicious = True

            # Condition 6: Direct SSH traffic
            if row['protocol'] == 'SSHv2':
                is_malicious = True

            # Condition 7: Traffic to SSH port
            if row.get('dest_port') == 22:
                is_malicious = True

            # Label the packet
            if is_malicious:
                labels.append('MALICIOUS')
            else:
                labels.append('BENIGN')

        return labels

    def create_labels_simple_brute_force(self, df):
        """Simple but effective brute force labeling for known brute force datasets."""
        labels = []

        # If you know ALL packets are from brute force attacks, use contextual clues
        for idx, row in df.iterrows():
            source_ip = row['source_ip']
            protocol = row['protocol']
            dest_port = row.get('dest_port', 0)
            info = str(row['info'])

            # Label as MALICIOUS if it shows brute force characteristics
            is_malicious = False

            # SSH-related traffic
            if protocol == 'SSHv2' or dest_port == 22:
                is_malicious = True

            # TCP connection attempts to SSH port
            elif dest_port == 22 and ('SYN' in info or 'ACK' in info):
                is_malicious = True

            # Connection failures/resets
            elif 'RST' in info or 'FIN' in info:
                is_malicious = True

            # High port source connections (common in brute force)
            elif row.get('source_port', 0) > 1024 and dest_port == 22:
                is_malicious = True

            if is_malicious:
                labels.append('MALICIOUS')
            else:
                labels.append('BENIGN')

        return labels

    def create_labels_aggregate_based(self, df):
        """Aggregate-based labeling that considers entire IP behavior."""
        # First pass: calculate IP-level statistics
        ip_stats = df.groupby('source_ip').agg({
            'timestamp': ['min', 'max', 'count'],
            'dest_port': lambda x: (x == 22).sum(),  # SSH attempts
            'protocol': lambda x: (x == 'SSHv2').sum(),  # SSH protocol
            'info': lambda x: x.str.contains('RST', na=False).sum()  # Failed connections
        }).round(4)

        # Flatten column names
        ip_stats.columns = ['first_seen', 'last_seen', 'total_packets', 'ssh_port_attempts', 'ssh_protocol_packets', 'failed_connections']

        # Calculate derived metrics
        ip_stats['session_duration'] = ip_stats['last_seen'] - ip_stats['first_seen']
        ip_stats['connection_rate'] = ip_stats['total_packets'] / (ip_stats['session_duration'] + 0.001)  # Avoid division by zero
        ip_stats['failure_rate'] = ip_stats['failed_connections'] / ip_stats['total_packets']
        ip_stats['ssh_ratio'] = (ip_stats['ssh_port_attempts'] + ip_stats['ssh_protocol_packets']) / ip_stats['total_packets']

        # Classify IPs as malicious (very permissive for brute force datasets)
        malicious_ips = ip_stats[
            (ip_stats['ssh_port_attempts'] >= 1) |  # 1+ SSH attempts
            (ip_stats['ssh_protocol_packets'] >= 1) |  # 1+ SSH protocol packets
            (ip_stats['connection_rate'] > 0.5) |   # > 0.5 connections/sec
            (ip_stats['failure_rate'] > 0.1) |     # > 10% failure rate
            (ip_stats['ssh_ratio'] > 0.3)          # > 30% SSH traffic
            ].index.tolist()

        # Label packets based on source IP classification
        labels = ['MALICIOUS' if row['source_ip'] in malicious_ips else 'BENIGN'
                  for _, row in df.iterrows()]

        return labels

    def create_labels(self, df, method='improved'):
        """Create threat classification labels using specified method."""
        if method == 'improved':
            return self.create_labels_improved(df)
        elif method == 'simple':
            return self.create_labels_simple_brute_force(df)
        elif method == 'aggregate':
            return self.create_labels_aggregate_based(df)
        else:
            # Original method with improvements
            labels = []
            for idx, row in df.iterrows():
                # Label as malicious if it shows brute force characteristics
                if (row.get('is_brute_force_indicator', 0) == 1 or
                        row.get('rapid_connections', 0) == 1 or
                        row.get('ssh_brute_force_pattern', 0) == 1 or
                        row.get('high_volume_ssh', 0) == 1 or
                        (row.get('connections_from_source', 0) > 2 and row.get('failure_rate', 0) > 0.2)):
                    labels.append('MALICIOUS')
                else:
                    labels.append('BENIGN')
            return labels

    def parse_dataset(self, csv_file, labeling_method='improved'):
        """Main parsing function that creates a comprehensive threat detection dataset."""
        try:
            # Check if file exists
            import os
            if not os.path.exists(csv_file):
                print(f"❌ ERROR: File '{csv_file}' not found!")
                print(f"📁 Current directory: {os.getcwd()}")
                print(f"📂 Files in current directory: {os.listdir('.')}")
                return None

            # Read CSV with error handling
            df = pd.read_csv(csv_file)
            print(f"✓ Successfully loaded {len(df)} records from {csv_file}")

            # Clean column names and handle potential variations
            df.columns = df.columns.str.strip()

            # Map column names to standard format
            column_mapping = {
                'No.': 'packet_num',
                'Time': 'timestamp',
                'Source': 'source_ip',
                'Destination': 'dest_ip',
                'Protocol': 'protocol',
                'Length': 'packet_length',
                'Info': 'info'
            }

            # Apply column mapping
            df = df.rename(columns=column_mapping)

            # Initialize feature containers
            all_features = []

            print("📊 Parsing network traffic features...")
            print(f"📋 Column names: {list(df.columns)}")

            # Parse each record
            for idx, row in df.iterrows():
                try:
                    features = {
                        'packet_id': idx + 1,
                        'original_packet_num': int(row['packet_num']),
                        'timestamp': float(row['timestamp']),
                        'source_ip': str(row['source_ip']),
                        'dest_ip': str(row['dest_ip']),
                        'protocol': str(row['protocol']),
                        'packet_length': int(row['packet_length']),
                        'info': str(row['info'])
                    }

                    # Parse TCP features
                    tcp_features = self.parse_tcp_features(row['info'])
                    features.update(tcp_features)

                    # Parse SSH features if applicable
                    if row['protocol'] == 'SSHv2':
                        ssh_features = self.parse_ssh_features(row['info'])
                        features.update(ssh_features)
                    else:
                        # Set default SSH features for non-SSH packets
                        ssh_defaults = {
                            'ssh_msg_type': 'NOT_SSH',
                            'ssh_role': 'NOT_SSH',
                            'ssh_kex_stage': 'NOT_SSH',
                            'ssh_dh_stage': 'NOT_SSH',
                            'ssh_packet_length': 0,
                            'ssh_version': 'NOT_SSH',
                            'ssh_implementation': 'NOT_SSH'
                        }
                        features.update(ssh_defaults)

                    all_features.append(features)

                except Exception as e:
                    print(f"⚠️ Error parsing row {idx}: {e}")
                    continue

            # Check if we have any features
            if not all_features:
                print("❌ ERROR: No features extracted from dataset!")
                return None

            # Convert to DataFrame
            parsed_df = pd.DataFrame(all_features)

            # Calculate threat indicators
            print("🔍 Calculating threat detection indicators...")
            threat_df = self.calculate_threat_indicators(parsed_df)

            # Combine all features
            final_df = pd.concat([parsed_df, threat_df], axis=1)

            # Create labels using specified method
            print(f"🏷️ Creating threat classification labels using '{labeling_method}' method...")
            final_df['threat_label'] = self.create_labels(final_df, method=labeling_method)

            # Add additional derived features
            final_df['is_connection_attempt'] = final_df['has_syn'].astype(int)
            final_df['is_connection_established'] = (
                    (final_df['has_syn'] == 1) & (final_df['has_ack'] == 1)
            ).astype(int)
            final_df['is_connection_terminated'] = (
                    (final_df['has_fin'] == 1) | (final_df['has_rst'] == 1)
            ).astype(int)

            # Calculate inter-packet timing
            final_df['inter_packet_time'] = final_df.groupby('source_ip')['timestamp'].diff().fillna(0)

            # Calculate connection frequency per source
            final_df['connection_frequency'] = final_df.groupby('source_ip')['is_connection_attempt'].transform('sum')

            print(f"✅ Dataset parsing completed!")
            print(f"📈 Final dataset shape: {final_df.shape}")
            print(f"🎯 Threat distribution: {final_df['threat_label'].value_counts().to_dict()}")

            return final_df

        except Exception as e:
            print(f"❌ Error in dataset parsing: {e}")
            print(f"🔍 Available columns: {list(df.columns) if 'df' in locals() else 'DataFrame not created'}")
            import traceback
            traceback.print_exc()
            return None

    def save_dataset(self, df, output_file='ssh_threat_detection_dataset.csv'):
        """Save the parsed dataset with proper formatting."""
        try:
            if df is None:
                print("❌ ERROR: No dataframe to save!")
                return None

            # Select and order columns for ML training
            feature_columns = [
                'packet_id', 'original_packet_num', 'timestamp', 'source_ip', 'dest_ip', 'protocol',
                'packet_length', 'source_port', 'dest_port', 'is_ssh_port',
                'has_syn', 'has_ack', 'has_fin', 'has_rst', 'has_psh', 'has_urg',
                'flag_count', 'connection_state', 'seq_num', 'ack_num', 'window_size',
                'tcp_length', 'mss', 'ts_val', 'ts_ecr', 'window_scale',
                'ssh_msg_type', 'ssh_role', 'ssh_kex_stage', 'ssh_dh_stage',
                'ssh_packet_length', 'ssh_version', 'ssh_implementation',
                'connections_from_source', 'failed_connections_from_source',
                'attempts_on_port', 'failure_rate', 'is_ssh_traffic', 'is_encrypted_ssh',
                'is_key_exchange', 'is_brute_force_indicator', 'rapid_connections',
                'ssh_brute_force_pattern', 'high_volume_ssh', 'connection_rate',
                'ssh_attempts_from_source', 'session_duration',
                'is_connection_attempt', 'is_connection_established', 'is_connection_terminated',
                'inter_packet_time', 'connection_frequency', 'threat_label'
            ]

            # Filter available columns
            available_columns = [col for col in feature_columns if col in df.columns]
            final_df = df[available_columns].copy()

            # Fill any remaining NaN values
            final_df = final_df.fillna(0)

            # Convert boolean columns to int for consistency
            bool_columns = ['is_ssh_port', 'has_syn', 'has_ack', 'has_fin', 'has_rst',
                            'has_psh', 'has_urg', 'is_ssh_traffic', 'is_encrypted_ssh',
                            'is_key_exchange', 'is_brute_force_indicator', 'rapid_connections',
                            'ssh_brute_force_pattern', 'high_volume_ssh',
                            'is_connection_attempt', 'is_connection_established', 'is_connection_terminated']

            for col in bool_columns:
                if col in final_df.columns:
                    final_df[col] = final_df[col].astype(int)

            # Save to CSV
            final_df.to_csv(output_file, index=False)
            print(f"💾 Dataset saved to {output_file}")

            # Verify file was created
            import os
            if os.path.exists(output_file):
                file_size = os.path.getsize(output_file)
                print(f"✅ File successfully created: {output_file} ({file_size:,} bytes)")
            else:
                print(f"❌ ERROR: File was not created: {output_file}")

            # Print summary statistics
            print("\n📊 Dataset Summary:")
            print(f"Total records: {len(final_df)}")
            print(f"Total features: {len(final_df.columns)}")
            print(f"Malicious records: {sum(final_df['threat_label'] == 'MALICIOUS')}")
            print(f"Benign records: {sum(final_df['threat_label'] == 'BENIGN')}")

            # Feature breakdown
            print(f"\n🔍 Feature Breakdown:")
            print(f"TCP Features: {len([c for c in final_df.columns if 'tcp' in c.lower() or c.startswith('has_') or c in ['source_port', 'dest_port', 'seq_num', 'ack_num', 'window_size']])}")
            print(f"SSH Features: {len([c for c in final_df.columns if 'ssh' in c.lower()])}")
            print(f"Threat Indicators: {len([c for c in final_df.columns if 'brute_force' in c or 'rapid' in c or 'failure' in c or 'connections_from' in c])}")

            # Show sample data
            print(f"\n📋 Sample Data (first 5 rows):")
            print(final_df.head())

            return final_df

        except Exception as e:
            print(f"❌ Error saving dataset: {e}")
            import traceback
            traceback.print_exc()
            return None

def main():
    """Main execution function."""
    print("🚀 SSH Brute Force Threat Detection Dataset Parser")
    print("=" * 50)

    # Initialize parser
    parser = SSHThreatParser()

    # Parse the dataset with different labeling methods
    # Options: 'improved', 'simple', 'aggregate', 'original'
    labeling_method = 'improved'  # Change this to test different methods

    try:
        # Note: Changed filename to match what's likely in the directory
        input_file = 'abnormal.csv'

        parsed_df = parser.parse_dataset(input_file, labeling_method=labeling_method)

        if parsed_df is not None:
            # Save the parsed dataset
            final_df = parser.save_dataset(parsed_df)

            if final_df is not None:
                print("\n🎉 Dataset parsing completed successfully!")
                print(f"📁 Output file: ssh_threat_detection_dataset.csv")

                # Display final statistics
                print("\n📊 Final Dataset Statistics:")
                print(f"• Total packets processed: {len(final_df):,}")
                print(f"• Total features extracted: {len(final_df.columns)}")
                print(f"• Unique source IPs: {final_df['source_ip'].nunique()}")
                print(f"• Unique destination IPs: {final_df['dest_ip'].nunique()}")

                # Protocol distribution
                print(f"\n🌐 Protocol Distribution:")
                protocol_counts = final_df['protocol'].value_counts()
                for protocol, count in protocol_counts.items():
                    print(f"• {protocol}: {count:,} packets ({count/len(final_df)*100:.1f}%)")

                # Threat label distribution
                print(f"\n🎯 Threat Classification Results:")
                threat_counts = final_df['threat_label'].value_counts()
                for label, count in threat_counts.items():
                    print(f"• {label}: {count:,} packets ({count/len(final_df)*100:.1f}%)")

                # SSH-specific statistics
                ssh_packets = final_df[final_df['protocol'] == 'SSHv2']
                if len(ssh_packets) > 0:
                    print(f"\n🔐 SSH Traffic Analysis:")
                    print(f"• Total SSH packets: {len(ssh_packets):,}")
                    print(f"• SSH message types: {ssh_packets['ssh_msg_type'].nunique()}")
                    print(f"• Encrypted SSH packets: {ssh_packets['is_encrypted_ssh'].sum():,}")
                    print(f"• Key exchange packets: {ssh_packets['is_key_exchange'].sum():,}")

                # Brute force indicators
                brute_force_indicators = final_df[final_df['is_brute_force_indicator'] == 1]
                if len(brute_force_indicators) > 0:
                    print(f"\n🚨 Brute Force Detection:")
                    print(f"• Packets with brute force indicators: {len(brute_force_indicators):,}")
                    print(f"• Rapid connection attempts: {final_df['rapid_connections'].sum():,}")
                    print(f"• SSH brute force patterns: {final_df['ssh_brute_force_pattern'].sum():,}")
                    print(f"• High volume SSH activities: {final_df['high_volume_ssh'].sum():,}")

                # Connection state analysis
                print(f"\n🔗 Connection State Analysis:")
                connection_states = final_df['connection_state'].value_counts()
                for state, count in connection_states.items():
                    print(f"• {state}: {count:,} packets")

                # Top source IPs by connection attempts
                print(f"\n🌍 Top Source IPs by Connection Attempts:")
                top_sources = final_df.groupby('source_ip')['connections_from_source'].first().sort_values(ascending=False).head(5)
                for ip, connections in top_sources.items():
                    print(f"• {ip}: {connections:,} connections")

                # Feature quality check
                print(f"\n✅ Data Quality Check:")
                missing_values = final_df.isnull().sum().sum()
                print(f"• Missing values: {missing_values:,}")
                print(f"• Data completeness: {((len(final_df) * len(final_df.columns) - missing_values) / (len(final_df) * len(final_df.columns)) * 100):.1f}%")

                # ML readiness assessment
                print(f"\n🤖 Machine Learning Readiness:")
                numeric_features = final_df.select_dtypes(include=[np.number]).columns
                categorical_features = final_df.select_dtypes(include=['object']).columns
                print(f"• Numeric features: {len(numeric_features)}")
                print(f"• Categorical features: {len(categorical_features)}")

                # Check for class imbalance
                if 'threat_label' in final_df.columns:
                    malicious_ratio = (final_df['threat_label'] == 'MALICIOUS').mean()
                    if malicious_ratio < 0.1 or malicious_ratio > 0.9:
                        print(f"⚠️  Class imbalance detected: {malicious_ratio:.1%} malicious packets")
                        print("   Consider using balanced sampling or cost-sensitive learning")
                    else:
                        print(f"✅ Reasonable class balance: {malicious_ratio:.1%} malicious packets")

                print(f"\n📋 Next Steps:")
                print("1. Review the generated dataset for accuracy")
                print("2. Consider feature engineering based on domain knowledge")
                print("3. Split data into training/validation/test sets")
                print("4. Apply appropriate ML algorithms for threat detection")
                print("5. Evaluate model performance using relevant metrics")

                return final_df
            else:
                print("❌ Failed to save the dataset")
                return None
        else:
            print("❌ Failed to parse the dataset")
            return None

    except FileNotFoundError:
        print(f"❌ ERROR: Input file '{input_file}' not found!")
        print("Please ensure the CSV file exists in the current directory")
        print("Expected format: packet_number, timestamp, source_ip, dest_ip, protocol, length, info")
        return None

    except Exception as e:
        print(f"❌ Unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = main()

    if result is not None:
        print(f"\n🎊 Processing completed successfully!")
        print(f"Dataset ready for machine learning applications")
    else:
        print(f"\n💥 Processing failed. Please check the error messages above.")