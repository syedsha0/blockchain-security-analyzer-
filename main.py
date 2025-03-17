import argparse
import sys
import json
from web3 import Web3
from blockchain_analyzer import BlockchainSecurityAnalyzer
from smart_contract_scanner import SmartContractScanner
from transaction_analyzer import TransactionAnalyzer

def main():
    parser = argparse.ArgumentParser(description='Blockchain Security Analysis Tool')
    parser.add_argument('address', help='Blockchain address to analyze')
    parser.add_argument('--blockchain', default='ethereum', choices=['ethereum'], 
                        help='Blockchain network (currently only Ethereum is supported)')
    parser.add_argument('--provider', default='infura', choices=['infura', 'alchemy', 'local'],
                        help='Web3 provider to use')
    parser.add_argument('--api-key', help='API key for the provider')
    parser.add_argument('--output', default='report', choices=['json', 'txt', 'both'],
                        help='Output format for the report')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()
    
    # Set up Web3 provider
    if args.provider == 'infura':
        api_key = args.api_key or "YOUR_INFURA_API_KEY"
        provider_url = f"https://mainnet.infura.io/v3/{api_key}"
    elif args.provider == 'alchemy':
        api_key = args.api_key or "YOUR_ALCHEMY_API_KEY"
        provider_url = f"https://eth-mainnet.alchemyapi.io/v2/{api_key}"
    elif args.provider == 'local':
        provider_url = "http://localhost:8545"
    else:
        print(f"Unsupported provider: {args.provider}")
        sys.exit(1)
        
    try:
        w3 = Web3(Web3.HTTPProvider(provider_url))
        if not w3.is_connected():
            print(f"Failed to connect to {args.blockchain} using {args.provider}")
            sys.exit(1)
            
        print(f"Connected to {args.blockchain} using {args.provider}")
        
        # Validate address
        if not w3.is_address(args.address):
            print(f"Invalid {args.blockchain} address: {args.address}")
            sys.exit(1)
            
        # Create analyzers
        blockchain_analyzer = BlockchainSecurityAnalyzer(args.blockchain)
        contract_scanner = SmartContractScanner(w3)
        transaction_analyzer = TransactionAnalyzer(w3, args.blockchain)
        
        print(f"\n{'='*50}")
        print(f"BLOCKCHAIN SECURITY ANALYSIS FOR {args.address}")
        print(f"{'='*50}\n")
        
        # Step 1: Analyze transactions
        print("Step 1: Analyzing transaction history...")
        tx_analysis = transaction_analyzer.analyze_transactions(args.address)
        
        print(f"- Found {tx_analysis['total_transactions']} transactions")
        if tx_analysis.get('high_value_transactions', 0) > 0:
            print(f"- Detected {tx_analysis['high_value_transactions']} high-value transactions")
        if tx_analysis.get('malicious_interactions', 0) > 0:
            print(f"- WARNING: Detected {tx_analysis['malicious_interactions']} interactions with known malicious addresses")
        if tx_analysis['anomalies']:
            print("- Anomalies detected:")
            for anomaly in tx_analysis['anomalies']:
                print(f"  * {anomaly}")
                
        # Step 2: Scan smart contract (if applicable)
        print("\nStep 2: Checking for smart contract...")
        contract_analysis = contract_scanner.scan_contract(args.address)
        
        if contract_analysis['is_contract']:
            print(f"- Address is a smart contract")
            print(f"- Contract is {'verified' if contract_analysis['verified'] else 'not verified'}")
            print(f"- Found {contract_analysis['vulnerability_count']} potential vulnerabilities")
            if contract_analysis['critical_vulnerabilities'] > 0:
                print(f"- WARNING: Detected {contract_analysis['critical_vulnerabilities']} critical vulnerabilities")
                
            if contract_analysis['vulnerabilities']:
                print("\n  Vulnerabilities:")
                for vuln in contract_analysis['vulnerabilities']:
                    print(f"  * [{vuln['severity']}] {vuln['name']}: {vuln['description']}")
        else:
            print("- Address is not a smart contract")
            
        # Step 3: Calculate overall security score
        print("\nStep 3: Calculating security score...")
        security_score = blockchain_analyzer.calculate_security_score(
            args.address, 
            tx_analysis, 
            contract_analysis
        )
        
        print(f"- Security Score: {security_score['score']}/100 ({security_score['risk_level']} Risk)")
        print(f"- Deductions: {security_score['deductions']} points")
        
        # Step 4: Generate recommendations
        print("\nStep 4: Generating security recommendations...")
        recommendations = blockchain_analyzer.generate_recommendations(tx_analysis, contract_analysis)
        
        print("- Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
            
        # Step 5: Generate visualizations if requested
        if args.visualize:
            print("\nStep 5: Generating visualizations...")
            if tx_analysis['total_transactions'] > 0:
                transaction_analyzer.visualize_transaction_patterns(tx_analysis)
                print("- Transaction patterns visualization saved")
                
            # Create a combined report with all data
            report = {
                "address": args.address,
                "blockchain": args.blockchain,
                "analysis_time": blockchain_analyzer._get_current_time(),
                "security_score": security_score,
                "transaction_analysis": tx_analysis,
                "smart_contract_analysis": contract_analysis,
                "recommendations": recommendations
            }
            
            blockchain_analyzer.visualize_security_metrics(report)
            print("- Security metrics visualization saved")
            
        # Step 6: Export report
        print("\nStep 6: Exporting report...")
        
        # Create a combined report with all data
        report = {
            "address": args.address,
            "blockchain": args.blockchain,
            "analysis_time": blockchain_analyzer._get_current_time(),
            "security_score": security_score,
            "transaction_analysis": tx_analysis,
            "smart_contract_analysis": contract_analysis,
            "recommendations": recommendations
        }
        
        if args.output in ['json', 'both']:
            with open("security_report.json", "w") as f:
                json.dump(report, f, indent=2, default=str)
            print("- Report exported to security_report.json")
            
        if args.output in ['txt', 'both']:
            blockchain_analyzer.export_report(report, format="txt")
            print("- Report exported to security_report.txt")
            
        print("\nAnalysis complete!")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

