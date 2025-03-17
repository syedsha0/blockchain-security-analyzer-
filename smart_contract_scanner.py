import re
import json
from web3 import Web3

class SmartContractScanner:
    def __init__(self, web3_provider):
        self.w3 = web3_provider
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
    def _load_vulnerability_patterns(self):
        """Load vulnerability patterns from a predefined set"""
        # In a real implementation, these would be loaded from a database or file
        return {
            "reentrancy": {
                "pattern": r"\.call{value:",
                "severity": "Critical",
                "description": "Potential reentrancy vulnerability detected. The contract calls an external address before updating its state.",
                "recommendation": "Implement checks-effects-interactions pattern and consider using ReentrancyGuard."
            },
            "tx_origin": {
                "pattern": r"tx\.origin",
                "severity": "Critical",
                "description": "Using tx.origin for authorization is vulnerable to phishing attacks.",
                "recommendation": "Use msg.sender instead of tx.origin for authorization checks."
            },
            "unchecked_send": {
                "pattern": r"\.send\(|\.transfer\(",
                "severity": "High",
                "description": "Using send() or transfer() can cause the contract to fail if the recipient has a fallback function that uses more than 2300 gas.",
                "recommendation": "Use call() with proper return value checking and reentrancy protection."
            },
            "integer_overflow": {
                "pattern": r"\+\+|\+=|-=|\/=|\*=",
                "severity": "High",
                "description": "Potential integer overflow or underflow in arithmetic operations.",
                "recommendation": "Use SafeMath library or Solidity 0.8.x which has built-in overflow checking."
            },
            "timestamp_dependence": {
                "pattern": r"block\.timestamp|now",
                "severity": "Medium",
                "description": "Using block.timestamp for critical logic can be manipulated by miners.",
                "recommendation": "Avoid using block.timestamp for random number generation or precise timing."
            },
            "assembly_usage": {
                "pattern": r"assembly",
                "severity": "Medium",
                "description": "Using assembly bypasses Solidity safety checks.",
                "recommendation": "Minimize the use of assembly and ensure it's thoroughly audited."
            },
            "floating_pragma": {
                "pattern": r"pragma solidity \^",
                "severity": "Low",
                "description": "Using a floating pragma version.",
                "recommendation": "Lock the pragma to a specific Solidity version."
            },
            "public_function": {
                "pattern": r"function\s+\w+\s*$$[^)]*$$\s+public",
                "severity": "Informational",
                "description": "Public function that might not need to be public.",
                "recommendation": "Consider using more restrictive visibility modifiers if appropriate."
            }
        }
        
    def scan_contract(self, address):
        """Scan a smart contract for vulnerabilities"""
        # Check if address is a contract
        code = self.w3.eth.get_code(address)
        if code == b'':
            return {"is_contract": False}
            
        # Try to get verified source code (in a real implementation, this would use Etherscan API)
        source_code = self._get_source_code(address)
        
        if source_code:
            # Scan source code for vulnerabilities
            vulnerabilities = self._scan_source_code(source_code)
        else:
            # If source code is not available, analyze bytecode
            vulnerabilities = self._analyze_bytecode(code)
            
        # Get contract metadata
        metadata = self._get_contract_metadata(address)
        
        return {
            "is_contract": True,
            "verified": source_code is not None,
            "vulnerabilities": vulnerabilities,
            "vulnerability_count": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v["severity"] == "Critical"]),
            "metadata": metadata
        }
        
    def _get_source_code(self, address):
        """Get verified source code for a contract (mock implementation)"""
        # In a real implementation, this would use Etherscan API or similar
        # For demo purposes, we'll return None or a mock source code
        import random
        if random.random() < 0.3:  # 30% chance of having verified source code
            return """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            
            contract TokenSwap {
                mapping(address => uint256) public balances;
                address public owner;
                
                constructor() {
                    owner = msg.sender;
                }
                
                function deposit() public payable {
                    balances[msg.sender] += msg.value;
                }
                
                function withdraw(uint256 amount) public {
                    require(balances[msg.sender] >= amount, "Insufficient balance");
                    (bool success, ) = msg.sender.call{value: amount}("");
                    require(success, "Transfer failed");
                    balances[msg.sender] -= amount;
                }
                
                function transferOwnership(address newOwner) public {
                    require(tx.origin == owner, "Not authorized");
                    owner = newOwner;
                }
                
                function getBlockTimestamp() public view returns (uint256) {
                    return block.timestamp;
                }
            }
            """
        return None
        
    def _scan_source_code(self, source_code):
        """Scan source code for vulnerabilities"""
        vulnerabilities = []
        
        for vuln_id, vuln_info in self.vulnerability_patterns.items():
            pattern = vuln_info["pattern"]
            if re.search(pattern, source_code):
                # Find line numbers
                lines = source_code.split('\n')
                line_numbers = []
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        line_numbers.append(str(i + 1))
                
                vulnerability = {
                    "id": vuln_id,
                    "name": vuln_id.replace('_', ' ').title(),
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "recommendation": vuln_info["recommendation"],
                    "line_numbers": ", ".join(line_numbers)
                }
                vulnerabilities.append(vulnerability)
                
        return vulnerabilities
        
    def _analyze_bytecode(self, bytecode):
        """Analyze bytecode for vulnerabilities (simplified mock implementation)"""
        # In a real implementation, this would use sophisticated bytecode analysis
        # For demo purposes, we'll return some random vulnerabilities
        import random
        
        vulnerabilities = []
        potential_vulnerabilities = [
            {
                "id": "delegatecall",
                "name": "Unsafe Delegatecall",
                "severity": "Critical",
                "description": "The contract uses delegatecall with user-supplied arguments.",
                "recommendation": "Avoid using delegatecall with user-supplied arguments."
            },
            {
                "id": "selfdestruct",
                "name": "Selfdestruct Present",
                "severity": "High",
                "description": "The contract contains selfdestruct functionality.",
                "recommendation": "Implement proper access controls around selfdestruct functionality."
            },
            {
                "id": "unchecked_low_level_call",
                "name": "Unchecked Low-Level Call",
                "severity": "Medium",
                "description": "The contract uses low-level calls without checking the return value.",
                "recommendation": "Always check the return value of low-level calls."
            }
        ]
        
        # Randomly select 0-2 vulnerabilities
        num_vulnerabilities = random.randint(0, 3)
        if num_vulnerabilities > 0:
            selected_indices = random.sample(range(len(potential_vulnerabilities)), num_vulnerabilities)
            for idx in selected_indices:
                vulnerabilities.append(potential_vulnerabilities[idx])
                
        return vulnerabilities
        
    def _get_contract_metadata(self, address):
        """Get metadata for a contract (mock implementation)"""
        # In a real implementation, this would fetch actual contract data
        balance = self.w3.eth.get_balance(address)
        balance_eth = self.w3.from_wei(balance, 'ether')
        
        # Mock data
        return {
            "balance": f"{balance_eth:.4f} ETH",
            "creation_date": "2023-01-15",  # Mock date
            "transaction_count": 1256,  # Mock count
            "compiler_version": "v0.8.4+commit.c7e474f2"  # Mock version
        }

# Example usage
if __name__ == "__main__":
    # Connect to Ethereum network (using Infura in this example)
    w3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY"))
    
    # Create scanner
    scanner = SmartContractScanner(w3)
    
    # Example Ethereum contract address (Uniswap V2 Router)
    address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    
    # Scan contract
    result = scanner.scan_contract(address)
    
    # Print results
    print(f"Contract scan results for {address}:")
    print(f"Is contract: {result['is_contract']}")
    
    if result['is_contract']:
        print(f"Verified: {result['verified']}")
        print(f"Vulnerability count: {result['vulnerability_count']}")
        print(f"Critical vulnerabilities: {result['critical_vulnerabilities']}")
        
        if result['vulnerabilities']:
            print("\nVulnerabilities:")
            for vuln in result['vulnerabilities']:
                print(f"- [{vuln['severity']}] {vuln['name']}: {vuln['description']}")
                print(f"  Recommendation: {vuln.get('recommendation', 'N/A')}")
                if 'line_numbers' in vuln:
                    print(f"  Line numbers: {vuln['line_numbers']}")
                print()

