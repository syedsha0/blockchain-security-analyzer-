import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time

class TransactionAnalyzer:
    def __init__(self, web3_provider, blockchain="ethereum"):
        self.w3 = web3_provider
        self.blockchain = blockchain
        
        # Load known malicious addresses (in a real implementation, this would be a comprehensive database)
        self.known_malicious = self._load_malicious_addresses()
        
    def _load_malicious_addresses(self):
        """Load known malicious addresses"""
        # In a real implementation, this would load from a database or API
        # For demo purposes, we'll use a small hardcoded list
        return [
            "0x0000000000000000000000000000000000000000",  # Null address (just an example)
            "0x1234567890123456789012345678901234567890",  # Example address
            "0x9876543210987654321098765432109876543210"   # Example address
        ]
        
    def analyze_transactions(self, address, max_transactions=100):
        """Analyze transactions for security issues"""
        print(f"Analyzing transactions for {address}...")
        
        # Get transactions (in a real implementation, this would fetch actual transaction data)
        transactions = self._get_transactions(address, max_transactions)
        
        if not transactions:
            return {
                "total_transactions": 0,
                "anomalies": ["No transactions found"],
                "transactions": []
            }
            
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(transactions)
        
        # Analyze transaction patterns
        anomalies = []
        
        # Check for high-value transactions
        high_value_threshold = self._calculate_high_value_threshold(df)
        high_value_txs = df[df['value_eth'] > high_value_threshold]
        if not high_value_txs.empty:
            anomalies.append(f"Found {len(high_value_txs)} high-value transactions (>{high_value_threshold:.2f} ETH)")
            
        # Check for transactions to known malicious addresses
        malicious_txs = df[df['to'].isin(self.known_malicious)]
        if not malicious_txs.empty:
            anomalies.append(f"Found {len(malicious_txs)} transactions to known malicious addresses")
            
        # Check for unusual transaction frequency
        frequency_anomaly = self._check_transaction_frequency(df)
        if frequency_anomaly:
            anomalies.append(frequency_anomaly)
            
        # Check for unusual gas prices
        gas_anomaly = self._check_gas_prices(df)
        if gas_anomaly:
            anomalies.append(gas_anomaly)
            
        # Calculate risk scores for each transaction
        df = self._calculate_risk_scores(df)
        
        # Convert back to list of dictionaries for the result
        result_transactions = df.to_dict('records')
        
        return {
            "total_transactions": len(transactions),
            "high_value_transactions": len(high_value_txs),
            "malicious_interactions": len(malicious_txs),
            "anomalies": anomalies,
            "transactions": result_transactions
        }
        
    def _get_transactions(self, address, max_transactions):
        """Get transactions for an address (mock implementation)"""
        # In a real implementation, this would fetch actual transaction data
        # For demo purposes, we'll generate mock data
        
        # Simulate API call delay
        time.sleep(1)
        
        transactions = []
        current_time = datetime.now()
        
        # Generate random transactions
        for i in range(np.random.randint(10, max_transactions)):
            # Random timestamp within the last 30 days
            days_ago = np.random.randint(0, 30)
            hours_ago = np.random.randint(0, 24)
            minutes_ago = np.random.randint(0, 60)
            tx_time = current_time - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
            
            # Determine if this is an outgoing transaction
            is_outgoing = np.random.random() < 0.5
            
            # Generate value with occasional high values
            if np.random.random() < 0.1:  # 10% chance of high value
                value_eth = np.random.uniform(5.0, 50.0)
            else:
                value_eth = np.random.uniform(0.001, 5.0)
                
            # Generate gas price (in Gwei)
            if np.random.random() < 0.05:  # 5% chance of unusually high gas
                gas_price = np.random.uniform(100.0, 500.0)
            else:
                gas_price = np.random.uniform(10.0, 100.0)
                
            # Generate random addresses
            from_addr = address if is_outgoing else f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(40)])}"
            
            # Small chance of sending to a known malicious address
            if is_outgoing and np.random.random() < 0.05:  # 5% chance
                to_addr = np.random.choice(self.known_malicious)
            else:
                to_addr = f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(40)])}" if is_outgoing else address
                
            # Determine if this is a contract interaction
            is_contract = np.random.random() < 0.3  # 30% chance
            
            transaction = {
                "hash": f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(64)])}",
                "from": from_addr,
                "to": to_addr,
                "value_eth": value_eth,
                "gas_price_gwei": gas_price,
                "timestamp": tx_time.timestamp(),
                "datetime": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                "is_contract_interaction": is_contract,
                "is_outgoing": is_outgoing
            }
            
            transactions.append(transaction)
            
        # Sort by timestamp (newest first)
        transactions.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return transactions
        
    def _calculate_high_value_threshold(self, df):
        """Calculate threshold for high-value transactions"""
        if df.empty:
            return 5.0  # Default threshold
            
        # Use 95th percentile or at least 5 ETH
        threshold = max(5.0, df['value_eth'].quantile(0.95))
        return threshold
        
    def _check_transaction_frequency(self, df):
        """Check for unusual transaction frequency"""
        if len(df) < 5:
            return None  # Not enough transactions to analyze
            
        # Group by day and count transactions
        df['date'] = pd.to_datetime(df['datetime']).dt.date
        daily_counts = df.groupby('date').size()
        
        # Calculate mean and standard deviation
        mean_count = daily_counts.mean()
        std_count = daily_counts.std()
        
        # Check for days with unusually high transaction counts (> mean + 2*std)
        high_frequency_days = daily_counts[daily_counts > mean_count + 2*std_count]
        
        if not high_frequency_days.empty:
            return f"Unusual transaction frequency detected on {len(high_frequency_days)} days"
            
        return None
        
    def _check_gas_prices(self, df):
        """Check for unusual gas prices"""
        if df.empty:
            return None
            
        # Calculate mean and standard deviation
        mean_gas = df['gas_price_gwei'].mean()
        std_gas = df['gas_price_gwei'].std()
        
        # Check for transactions with unusually high gas prices (> mean + 3*std)
        high_gas_txs = df[df['gas_price_gwei'] > mean_gas + 3*std_gas]
        
        if not high_gas_txs.empty:
            return f"Unusually high gas prices detected in {len(high_gas_txs)} transactions"
            
        return None
        
    def _calculate_risk_scores(self, df):
        """Calculate risk scores for each transaction"""
        # Initialize risk score
        df['risk_score'] = 0
        
        # High value transactions
        high_value_threshold = self._calculate_high_value_threshold(df)
        df.loc[df['value_eth'] > high_value_threshold, 'risk_score'] += 30
        
        # Transactions to known malicious addresses
        df.loc[df['to'].isin(self.known_malicious), 'risk_score'] += 70
        
        # Unusual gas prices
        mean_gas = df['gas_price_gwei'].mean()
        std_gas = df['gas_price_gwei'].std()
        df.loc[df['gas_price_gwei'] > mean_gas + 3*std_gas, 'risk_score'] += 20
        
        # Contract interactions (slightly higher risk)
        df.loc[df['is_contract_interaction'], 'risk_score'] += 10
        
        # Cap risk score at 100
        df['risk_score'] = df['risk_score'].clip(0, 100)
        
        # Add risk level based on score
        df['risk_level'] = 'Low'
        df.loc[df['risk_score'] >= 50, 'risk_level'] = 'Medium'
        df.loc[df['risk_score'] >= 75, 'risk_level'] = 'High'
        
        return df
        
    def visualize_transaction_patterns(self, analysis_result, output_file="transaction_patterns.png"):
        """Visualize transaction patterns"""
        if not analysis_result["transactions"]:
            print("No transactions to visualize")
            return
            
        # Convert to DataFrame
        df = pd.DataFrame(analysis_result["transactions"])
        
        # Create figure with subplots
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 15))
        
        # 1. Transaction values over time
        df['datetime'] = pd.to_datetime(df['datetime'])
        df = df.sort_values('datetime')
        
        ax1.scatter(df['datetime'], df['value_eth'], c=df['risk_score'], cmap='YlOrRd', alpha=0.7)
        ax1.set_title('Transaction Values Over Time')
        ax1.set_xlabel('Date')
        ax1.set_ylabel('Value (ETH)')
        ax1.grid(True, linestyle='--', alpha=0.7)
        
        # Add colorbar for risk score
        cbar = plt.colorbar(ax1.collections[0], ax=ax1)
        cbar.set_label('Risk Score')
        
        # 2. Risk distribution pie chart
        risk_counts = df['risk_level'].value_counts()
        colors = {'Low': 'green', 'Medium': 'orange', 'High': 'red'}
        risk_colors = [colors[level] for level in risk_counts.index]
        
        ax2.pie(risk_counts, labels=risk_counts.index, autopct='%1.1f%%', 
                startangle=90, colors=risk_colors)
        ax2.set_title('Transaction Risk Distribution')
        ax2.axis('equal')
        
        # 3. Transaction frequency by day
        df['date'] = df['datetime'].dt.date
        daily_counts = df.groupby('date').size()
        
        ax3.bar(daily_counts.index, daily_counts.values, color='skyblue')
        ax3.set_title('Transaction Frequency by Day')
        ax3.set_xlabel('Date')
        ax3.set_ylabel('Number of Transactions')
        ax3.grid(True, axis='y', linestyle='--', alpha=0.7)
        
        # Rotate date labels for better readability
        plt.setp(ax3.get_xticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        
        print(f"Transaction patterns visualization saved to {output_file}")

# Example usage
if __name__ == "__main__":
    from web3 import Web3
    
    # Connect to Ethereum network (using Infura in this example)
    w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY"))
    
    # Create analyzer
    analyzer = TransactionAnalyzer(w3)
    
    # Example Ethereum address
    address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
    
    # Analyze transactions
    result = analyzer.analyze_transactions(address)
    
    # Print results
    print(f"Transaction analysis results for {address}:")
    print(f"Total transactions: {result['total_transactions']}")
    print(f"High value transactions: {result.get('high_value_transactions', 0)}")
    print(f"Interactions with malicious addresses: {result.get('malicious_interactions', 0)}")
    
    if result['anomalies']:
        print("\nAnomalies detected:")
        for anomaly in result['anomalies']:
            print(f"- {anomaly}")
            
    # Visualize transaction patterns
    analyzer.visualize_transaction_patterns(result)

