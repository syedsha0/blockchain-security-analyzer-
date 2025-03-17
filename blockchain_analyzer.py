import requests
import json
import time
from datetime import datetime
import hashlib
import matplotlib.pyplot as plt
import numpy as np
from web3 import Web3

class BlockchainSecurityAnalyzer:
    def __init__(self, blockchain="ethereum"):
        self.blockchain = blockchain
        # In a real implementation, you would use actual API keys
        self.api_keys = {
            "etherscan": "YOUR_ETHERSCAN_API_KEY",
            "infura": "YOUR_INFURA_API_KEY"
        }
        
        # Connect to blockchain node (using Infura for Ethereum in this example)
        if blockchain == "ethereum":
            self.w3 = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{self.api_keys['infura']}"))
        else:
            raise ValueError(f"Blockchain {blockchain} not supported")
            
        print(f"Connected to {blockchain}: {self.w3.is_connected()}")
        
    def analyze_address(self, address):
        """Main function to analyze a blockchain address"""
        if not self.w3.is_address(address):
            raise ValueError(f"Invalid {self.blockchain} address: {address}")
            
        print(f"Starting security analysis for address: {address}")
        
        # Collect all data
        transaction_data = self.analyze_transactions(address)
        contract_data = self.analyze_smart_contract(address)
        security_score = self.calculate_security_score(address, transaction_data, contract_data)
        
        # Generate report
        report = {
            "address": address,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "blockchain": self.blockchain,
            "security_score": security_score,
            "transaction_analysis": transaction_data,
            "smart_contract_analysis": contract_data,
            "recommendations": self.generate_recommendations(transaction_data, contract_data)
        }
        
        return report
        
    def analyze_transactions(self, address):
        """Analyze transaction patterns for security issues"""
        print(f"Analyzing transactions for {address}...")
        
        # In a real implementation, you would fetch actual transaction data
        # For demo purposes, we'll create mock data
        
        # Simulate API call delay
        time.sleep(1)
        
        # Mock transaction data
        transactions = self._get_mock_transactions(address)
        
        # Analyze transaction patterns
        high_value_txs = [tx for tx in transactions if float(tx["value"]) > 10.0]
        unusual_contracts = [tx for tx in transactions if tx.get("is_contract_interaction") and tx.get("contract_verified") is False]
        suspicious_patterns = self._detect_suspicious_patterns(transactions)
        
        return {
            "total_transactions": len(transactions),
            "high_value_transactions": len(high_value_txs),
            "unusual_contract_interactions": len(unusual_contracts),
            "suspicious_patterns": suspicious_patterns,
            "transaction_sample": transactions[:5]  # First 5 transactions as sample
        }
        
    def analyze_smart_contract(self, address):
        """Analyze smart contract security if the address is a contract"""
        print(f"Checking if {address} is a smart contract...")
        
        # Check if address is a contract
        code = self.w3.eth.get_code(address)
        is_contract = code != b''
        
        if not is_contract:
            print(f"{address} is not a smart contract")
            return {"is_contract": False}
            
        print(f"{address} is a smart contract. Analyzing...")
        
        # In a real implementation, you would decompile and analyze the contract
        # For demo purposes, we'll create mock data
        
        # Simulate analysis delay
        time.sleep(2)
        
        vulnerabilities = self._scan_mock_vulnerabilities()
        
        return {
            "is_contract": True,
            "bytecode_hash": hashlib.sha256(code).hexdigest(),
            "verified": self._is_mock_contract_verified(),
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v["severity"] == "Critical"])
        }
        
    def calculate_security_score(self, address, transaction_data, contract_data):
        """Calculate an overall security score based on various factors"""
        base_score = 100
        deductions = 0
        
        # Transaction-based deductions
        if transaction_data["high_value_transactions"] > 0:
            deductions += min(10, transaction_data["high_value_transactions"] * 2)
            
        if transaction_data["unusual_contract_interactions"] > 0:
            deductions += min(15, transaction_data["unusual_contract_interactions"] * 3)
            
        if len(transaction_data["suspicious_patterns"]) > 0:
            deductions += min(25, len(transaction_data["suspicious_patterns"]) * 5)
            
        # Contract-based deductions (if applicable)
        if contract_data.get("is_contract", False):
            if not contract_data.get("verified", False):
                deductions += 15
                
            critical_vulns = contract_data.get("critical_vulnerabilities", 0)
            if critical_vulns > 0:
                deductions += min(40, critical_vulns * 10)
                
            total_vulns = contract_data.get("vulnerability_count", 0)
            if total_vulns > 0:
                deductions += min(20, total_vulns * 2)
                
        # Calculate final score
        final_score = max(0, base_score - deductions)
        
        # Determine risk level
        risk_level = "Low"
        if final_score < 50:
            risk_level = "High"
        elif final_score < 75:
            risk_level = "Medium"
            
        return {
            "score": final_score,
            "risk_level": risk_level,
            "deductions": deductions
        }
        
    def generate_recommendations(self, transaction_data, contract_data):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Transaction-based recommendations
        if transaction_data["high_value_transactions"] > 0:
            recommendations.append("Consider using multi-signature wallets for high-value transactions")
            
        if transaction_data["unusual_contract_interactions"] > 0:
            recommendations.append("Review and verify all smart contracts before interaction")
            
        if len(transaction_data["suspicious_patterns"]) > 0:
            recommendations.append("Monitor account for unusual activity and consider using a hardware wallet")
            
        # Contract-based recommendations
        if contract_data.get("is_contract", False):
            if not contract_data.get("verified", False):
                recommendations.append("Verify your contract source code on block explorers for transparency")
                
            if contract_data.get("critical_vulnerabilities", 0) > 0:
                recommendations.append("Address critical vulnerabilities in your smart contract immediately")
                
            if contract_data.get("vulnerability_count", 0) > 0:
                recommendations.append("Conduct a professional security audit of your smart contract")
                
        # General recommendations
        recommendations.append("Regularly monitor your address for suspicious activities")
        recommendations.append("Use hardware wallets for storing significant assets")
        recommendations.append("Implement proper key management practices")
        
        return recommendations
        
    def visualize_security_metrics(self, report):
        """Generate visualizations for security metrics"""
        # Create a figure with multiple subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Security score gauge chart
        score = report["security_score"]["score"]
        gauge_colors = ['red', 'orange', 'yellow', 'yellowgreen', 'green']
        gauge_bounds = [0, 20, 40, 60, 80, 100]
        
        # Determine color based on score
        color_idx = 0
        for i, bound in enumerate(gauge_bounds[1:]):
            if score <= bound:
                color_idx = i
                break
                
        ax1.pie([score, 100-score], colors=[gauge_colors[color_idx], 'whitesmoke'], 
                startangle=90, counterclock=False, 
                wedgeprops={'width': 0.3, 'edgecolor': 'w'})
        ax1.text(0, 0, f"{score}", ha='center', va='center', fontsize=24)
        ax1.text(0, -0.2, "Security Score", ha='center', va='center', fontsize=12)
        ax1.set_title("Security Score")
        ax1.axis('equal')
        
        # Vulnerability breakdown (if contract)
        if report["smart_contract_analysis"].get("is_contract", False):
            vulnerabilities = report["smart_contract_analysis"]["vulnerabilities"]
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            
            for vuln in vulnerabilities:
                severity = vuln["severity"]
                severity_counts[severity] += 1
                
            labels = list(severity_counts.keys())
            sizes = list(severity_counts.values())
            colors = ['darkred', 'red', 'orange', 'yellow', 'blue']
            
            # Only plot if there are vulnerabilities
            if sum(sizes) > 0:
                ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax2.axis('equal')
                ax2.set_title("Vulnerability Severity Breakdown")
            else:
                ax2.text(0.5, 0.5, "No vulnerabilities detected", ha='center', va='center')
                ax2.axis('off')
        else:
            ax2.text(0.5, 0.5, "Not a smart contract", ha='center', va='center')
            ax2.axis('off')
            
        plt.tight_layout()
        plt.savefig("security_metrics.png")
        plt.close()
        
        print("Security metrics visualization saved to security_metrics.png")
        
    def export_report(self, report, format="json"):
        """Export the security report in various formats"""
        if format == "json":
            with open("security_report.json", "w") as f:
                json.dump(report, f, indent=2)
            print("Report exported to security_report.json")
            
        elif format == "txt":
            with open("security_report.txt", "w") as f:
                f.write(f"BLOCKCHAIN SECURITY ANALYSIS REPORT\n")
                f.write(f"================================\n\n")
                f.write(f"Address: {report['address']}\n")
                f.write(f"Blockchain: {report['blockchain']}\n")
                f.write(f"Analysis Time: {report['analysis_time']}\n\n")
                
                f.write(f"SECURITY SCORE: {report['security_score']['score']}/100 ({report['security_score']['risk_level']} Risk)\n\n")
                
                f.write(f"TRANSACTION ANALYSIS\n")
                f.write(f"--------------------\n")
                tx_data = report['transaction_analysis']
                f.write(f"Total Transactions: {tx_data['total_transactions']}\n")
                f.write(f"High Value Transactions: {tx_data['high_value_transactions']}\n")
                f.write(f"Unusual Contract Interactions: {tx_data['unusual_contract_interactions']}\n")
                
                if tx_data['suspicious_patterns']:
                    f.write(f"\nSuspicious Patterns Detected:\n")
                    for pattern in tx_data['suspicious_patterns']:
                        f.write(f"- {pattern}\n")
                        
                f.write(f"\nSMART CONTRACT ANALYSIS\n")
                f.write(f"-----------------------\n")
                contract_data = report['smart_contract_analysis']
                
                if contract_data.get('is_contract', False):
                    f.write(f"Contract Verified: {'Yes' if contract_data.get('verified', False) else 'No'}\n")
                    f.write(f"Total Vulnerabilities: {contract_data.get('vulnerability_count', 0)}\n")
                    f.write(f"Critical Vulnerabilities: {contract_data.get('critical_vulnerabilities', 0)}\n")
                    
                    if contract_data.get('vulnerabilities', []):
                        f.write(f"\nVulnerabilities:\n")
                        for vuln in contract_data['vulnerabilities']:
                            f.write(f"- [{vuln['severity']}] {vuln['name']}: {vuln['description']}\n")
                else:
                    f.write(f"Not a smart contract\n")
                    
                f.write(f"\nRECOMMENDATIONS\n")
                f.write(f"---------------\n")
                for rec in report['recommendations']:
                    f.write(f"- {rec}\n")
                    
            print("Report exported to security_report.txt")
        else:
            raise ValueError(f"Unsupported export format: {format}")
            
    # Helper methods for mock data generation
    def _get_mock_transactions(self, address):
        """Generate mock transaction data for demo purposes"""
        transactions = []
        
        # Generate 20 random transactions
        for i in range(20):
            is_outgoing = i % 2 == 0
            is_contract = i % 3 == 0
            
            tx = {
                "hash": f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(64)])}",
                "from": address if is_outgoing else f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(40)])}",
                "to": f"0x{''.join([format(np.random.randint(0, 16), 'x') for _ in range(40)])}" if is_outgoing else address,
                "value": f"{np.random.uniform(0.1, 20.0):.4f} ETH",
                "timestamp": (datetime.now().timestamp() - np.random.randint(1, 30) * 86400),
                "is_contract_interaction": is_contract,
                "contract_verified": is_contract and np.random.random() > 0.3
            }
            
            transactions.append(tx)
            
        return transactions
        
    def _detect_suspicious_patterns(self, transactions):
        """Detect suspicious patterns in transaction history"""
        patterns = []
        
        # For demo purposes, randomly add some suspicious patterns
        if np.random.random() < 0.7:
            patterns.append("Multiple high-value transactions in short time period")
            
        if np.random.random() < 0.5:
            patterns.append("Interaction with known high-risk contracts")
            
        if np.random.random() < 0.3:
            patterns.append("Unusual transaction pattern compared to historical behavior")
            
        if np.random.random() < 0.2:
            patterns.append("Transactions to addresses associated with scams")
            
        return patterns
        
    def _scan_mock_vulnerabilities(self):
        """Generate mock vulnerability data for demo purposes"""
        vulnerabilities = []
        
        # Common smart contract vulnerabilities
        potential_vulnerabilities = [
            {
                "name": "Reentrancy",
                "severity": "Critical",
                "description": "The contract is vulnerable to reentrancy attacks in the withdraw function",
                "code_snippet": "function withdraw(uint amount) public {\n    require(balances[msg.sender] >= amount);\n    (bool success, ) = msg.sender.call{value: amount}(\"\");\n    require(success);\n    balances[msg.sender] -= amount;\n}"
            },
            {
                "name": "Integer Overflow/Underflow",
                "severity": "High",
                "description": "Arithmetic operations can result in integer overflow or underflow",
                "code_snippet": "function transfer(address to, uint256 amount) public {\n    balances[msg.sender] -= amount;\n    balances[to] += amount;\n}"
            },
            {
                "name": "Unchecked External Call",
                "severity": "Medium",
                "description": "External call result is not checked properly",
                "code_snippet": "function distribute(address[] memory recipients) public {\n    for(uint i = 0; i < recipients.length; i++) {\n        recipients[i].call{value: 1 ether}(\"\");\n    }\n}"
            },
            {
                "name": "Timestamp Dependence",
                "severity": "Medium",
                "description": "Contract logic depends on block timestamp which can be manipulated by miners",
                "code_snippet": "function isExpired() public view returns (bool) {\n    return block.timestamp > expiryTime;\n}"
            },
            {
                "name": "Floating Pragma",
                "severity": "Low",
                "description": "Contract uses a floating pragma statement",
                "code_snippet": "pragma solidity ^0.8.0;"
            },
            {
                "name": "Visibility Not Specified",
                "severity": "Low",
                "description": "Function visibility is not explicitly specified",
                "code_snippet": "function transferOwnership(address newOwner) {\n    owner = newOwner;\n}"
            },
            {
                "name": "Unused Variables",
                "severity": "Informational",
                "description": "Contract contains unused state variables",
                "code_snippet": "uint256 private unusedVariable;"
            }
        ]
        
        # Randomly select 0-4 vulnerabilities
        num_vulnerabilities = np.random.randint(0, 5)
        if num_vulnerabilities > 0:
            selected_indices = np.random.choice(len(potential_vulnerabilities), num_vulnerabilities, replace=False)
            for idx in selected_indices:
                vulnerabilities.append(potential_vulnerabilities[idx])
                
        return vulnerabilities
        
    def _is_mock_contract_verified(self):
        """Randomly determine if the mock contract is verified"""
        return np.random.random() > 0.3

# Example usage
if __name__ == "__main__":
    analyzer = BlockchainSecurityAnalyzer()
    
    # Example Ethereum address (Uniswap V2 Router)
    address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    
    try:
        # Analyze the address
        report = analyzer.analyze_address(address)
        
        # Visualize security metrics
        analyzer.visualize_security_metrics(report)
        
        # Export the report
        analyzer.export_report(report, format="txt")
        analyzer.export_report(report, format="json")
        
        # Print summary
        print("\nSecurity Analysis Summary:")
        print(f"Address: {address}")
        print(f"Security Score: {report['security_score']['score']}/100 ({report['security_score']['risk_level']} Risk)")
        print(f"Transaction Count: {report['transaction_analysis']['total_transactions']}")
        
        if report['smart_contract_analysis'].get('is_contract', False):
            print(f"Contract Verified: {'Yes' if report['smart_contract_analysis'].get('verified', False) else 'No'}")
            print(f"Vulnerabilities: {report['smart_contract_analysis'].get('vulnerability_count', 0)}")
        else:
            print("Not a smart contract")
            
        print("\nTop Recommendations:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"{i}. {rec}")
            
    except Exception as e:
        print(f"Error during analysis: {e}")

