# Cloud Security Configuration Analyzer

A web application that analyzes cloud infrastructure configurations for security vulnerabilities using both predefined rules and AI-powered analysis.

## Overview

The solution provides:

- Rule-based security analysis for common cloud resources (VMs, databases, storage)
- AI-powered analysis for resources without predefined rules
- Integration with OpenAI's GPT-4 for intelligent security recommendations
- Web interface for uploading and analyzing configurations
- Detailed security findings with severity levels and remediation steps

### Architecture

```
CloudSecConfigAnalysis/
│
├── [app.py](http://_vscodecontentref_/0)                 # Flask web application
├── [main.py](http://_vscodecontentref_/1)               # Core analysis engine
│
├── models/               # Data models
│   ├── ai_findings.py    # AI analysis models
│   ├── resource.py       # Resource definitions
│   └── security_rule.py  # Security rules
│
├── rules/                # Security rule definitions
│   ├── virtual_machine/
│   ├── database/
│   └── storage_account/
│
├── static/               # Web assets
│   ├── style.css
│   └── script.js
│
├── templates/            # HTML templates
│   └── index.html
│
├── cis_benchmark/        # CIS guidelines
├── data/                 # Sample data
└── uploads/             # Temporary upload directory
```
## Assumptions and Design Decisions

### Security Rules
- Based on CIS Microsoft Azure Foundations Benchmark v3.0.0
- Focused on critical security controls for:
  - Virtual Machines (encryption, authentication, network security)
  - Databases (encryption, auditing, access control)
  - Storage Accounts (encryption, network access, SAS policies)

### Resource Configuration Format
```json
{
  "resources": [
    {
      "type": "resource_type",
      "name": "resource_name",
      "azure_specific": {
        //Resource-specific properties
      }
    }
  ]
}
```
### Optional AI Integration for other Resource types
- Uses OpenAI GPT-4 for analyzing resource types without predefined rules
- Leverages CIS benchmark documentation as context
- Returns findings in consistent format matching rule-based analysis
- Require openAI API keys and if not provided, just provides rule based analysis result

## Setup and Installation
1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/CloudSecConfigAnalysis.git
   cd CloudSecConfigAnalysis
   ```
2. **Create virtual environment**
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Linux/Mac
    source .venv/bin/activate
    ```
3. **Install dependencies**
    ```bash
    pip install -r requirements.txt # may need to use virtual envirnment path
    ```
4. **OpenAI API Setup (Optional)**
- Create account at [OpenAI Platform](https://platform.openai.com/docs/overview)
- Generate API key from dashboard
- Enter API key in web interface when analyzing configurations
- Skip this step to use only rule-based analysis

5. **Run the application**
    ```bash
    python app.py
    ```
6. **Access Web Interface**
- Navigate to http://localhost:5000
- Optionally Download template for refernce 
- Upload configuration JSON file
- Optionally enter OpenAI Key
- View analysis results in real-time


## Screenshots

1. **Web interface**

![alt text](/Screenshots/image.png)

2. **File Upload**

Accepts only json file
![alt text](/Screenshots/image-1.png)

3. **Rule-based findings**

![alt text](/Screenshots/image-2.png)
![alt text](/Screenshots/image-3.png)

4. AI-based findings

![alt text](/Screenshots/image-4.png)
![alt text](/Screenshots/image-5.png)


## Future Enhancements

1. **Additional Rules**

- Add rules for new resource types based on CIS benchmark and other Standards or create custom requirment:
    ```python
    def rulename_rule() -> SecurityRule:
    ```
2. **AI Capabilities**
- Implement RAG (Retrieval Augmented Generation):
    - Index security standards and best practices
    - Retrieve relevant context for each analysis
- Improve accuracy of AI recommendations using LLM as Judge by collecting metrics for each configuration, mesuring and providing feedback

3. **Security**
- Input validation of json and dropping any suspecious parameter syntax
- File size validation before processing
- Concurrent upload handling
- Cleanup of temporary files on error
- API key stored in keyvault while running the application/use

4. **Performance Optimization**
- Parallel Processing:
    - Process rule-based analysis in parallel
    - Stream results as they become available
    - Handle large configuration files efficiently
- Asynchronous Analysis:
    - Separate rule-based and AI analysis streams
    - Real-time UI updates
    - Background processing for long-running analyses
- Caching and Optimization:
    - Cache common findings
    - Optimize API calls
    - Reduce redundant analysis
